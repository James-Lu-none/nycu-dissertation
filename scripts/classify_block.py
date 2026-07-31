import os
import sys
import argparse
import tempfile
import subprocess
import joblib
import numpy as np
import torch
import umap
from sklearn.cluster import KMeans, HDBSCAN
from sklearn.metrics import silhouette_score
from transformers import AutoTokenizer, AutoModel
import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Parser

def get_parser(filename):
    parser = Parser()
    if filename.endswith(".c") or filename.endswith(".h"):
        parser.language = Language(tree_sitter_c.language())
    else:
        parser.language = Language(tree_sitter_cpp.language())
    return parser

class CachedSourceDir:
    def __init__(self, download_sh_path, bench_dir, bench_name):
        self.download_sh_path = download_sh_path
        # Navigate up from 'bench' directory to project root, then into 'tmp/bench_name'
        base_dir = os.path.dirname(os.path.abspath(bench_dir))
        self.src_cache_dir = os.path.join(base_dir, "tmp", bench_name)
        
    def __enter__(self):
        os.makedirs(self.src_cache_dir, exist_ok=True)
        # Check if already downloaded (directory is empty)
        if not os.listdir(self.src_cache_dir):
            try:
                if os.path.exists(self.download_sh_path):
                    subprocess.check_call(["bash", os.path.abspath(self.download_sh_path)], cwd=self.src_cache_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                print(f"Error executing download.sh: {e}")
                
        src_path = os.path.join(self.src_cache_dir, "src")
        if os.path.isdir(src_path):
            return src_path
        return self.src_cache_dir

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Do not delete the cache directory
        pass

def find_function_node(node, line_idx):
    if node.type in ["function_definition", "method_definition"]:
        if node.start_point[0] <= line_idx <= node.end_point[0]:
            return node
    
    for child in node.children:
        res = find_function_node(child, line_idx)
        if res:
            return res
    return None

def extract_context(src_dir, targets):
    contexts = []
    file_cache = {}
    
    # Pre-build a map of all files to avoid traversing the disk for every target
    file_map = {}
    for root, _, files in os.walk(src_dir):
        for f in files:
            if f not in file_map:
                file_map[f] = os.path.join(root, f)
                
    for t in targets:
        filename = t['filename']
        lineno = t['lineno']
        
        if filename not in file_cache:
            filepath = file_map.get(filename)
            if not filepath:
                contexts.append(None)
                continue
            
            with open(filepath, 'rb') as f:
                src_bytes = f.read()
                
            parser = get_parser(filename)
            tree = parser.parse(src_bytes)
            file_cache[filename] = {'bytes': src_bytes, 'tree': tree, 'lines': src_bytes.split(b'\n')}
            
        cache_entry = file_cache.get(filename)
        if not cache_entry:
            contexts.append(None)
            continue
            
        tree = cache_entry['tree']
        lines = cache_entry['lines']
        
        line_idx = lineno - 1
        if line_idx >= len(lines):
            contexts.append(None)
            continue
            
        func_node = find_function_node(tree.root_node, line_idx)
        
        if func_node:
            start_line = func_node.start_point[0]
            end_line = func_node.end_point[0]
        else:
            start_line = max(0, line_idx - 50)
            end_line = min(len(lines) - 1, line_idx + 50)
            
        if end_line - start_line > 1000:
            start_line = max(0, line_idx - 500)
            end_line = min(len(lines) - 1, line_idx + 500)
            
        extracted_lines = lines[start_line:end_line+1]
        context_code = b'\n'.join(extracted_lines).decode('utf-8', errors='ignore')
        
        target_local_idx = line_idx - start_line
        
        pre_text = b'\n'.join(extracted_lines[:target_local_idx])
        if pre_text:
            pre_text += b'\n'
        
        target_line_text = extracted_lines[target_local_idx]
        
        start_char_idx = len(pre_text.decode('utf-8', errors='ignore'))
        end_char_idx = start_char_idx + len(target_line_text.decode('utf-8', errors='ignore'))
        
        contexts.append({
            'context_code': context_code,
            'start_char': start_char_idx,
            'end_char': end_char_idx,
            'orig_target': t,
            'target_code': target_line_text.decode('utf-8', errors='ignore').strip()
        })
        
    return contexts

from tqdm import tqdm

def get_target_embeddings(contexts, model_name="jinaai/jina-embeddings-v2-base-code", batch_size=4):
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    # Load model in bfloat16 for heavily optimized inference on RTX 6000 Ada/Blackwell
    model = AutoModel.from_pretrained(model_name, trust_remote_code=True, torch_dtype=torch.bfloat16)
    
    # Force using only GPU 0 as requested by the professor
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    
    embeddings = []
    valid_contexts = []
    
    # Pre-filter out None contexts
    valid_ctxs = [ctx for ctx in contexts if ctx is not None]
    if not valid_ctxs:
        return np.array(embeddings), valid_contexts
        
    # Process in batches
    for i in tqdm(range(0, len(valid_ctxs), batch_size), desc="Computing Embeddings"):
        batch_ctxs = valid_ctxs[i:i + batch_size]
        batch_texts = [ctx['context_code'] for ctx in batch_ctxs]
        
        # Tokenize batch with padding
        encoded = tokenizer(
            batch_texts,
            return_tensors="pt",
            return_offsets_mapping=True,
            truncation=True,
            padding=True,
            max_length=8192
        )
        
        input_ids = encoded['input_ids'].to(device)
        attention_mask = encoded['attention_mask'].to(device)
        
        # Inference with Automatic Mixed Precision (AMP)
        with torch.no_grad():
            with torch.autocast(device_type='cuda', dtype=torch.bfloat16):
                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            
        last_hidden_state = outputs.last_hidden_state
        
        # Extract per-sample mean pooled embeddings
        for b_idx, ctx in enumerate(batch_ctxs):
            start_char = ctx['start_char']
            end_char = ctx['end_char']
            offsets = encoded['offset_mapping'][b_idx].numpy()
            
            target_token_indices = []
            for idx, (start_c, end_c) in enumerate(offsets):
                if start_c == end_c == 0:
                    continue
                if not (end_c <= start_char or start_c >= end_char):
                    target_token_indices.append(idx)
                    
            if not target_token_indices:
                continue
                
            target_states = last_hidden_state[b_idx, target_token_indices]
            # Convert back to float32 for CPU downstream processing (clustering)
            mean_pooled = target_states.mean(dim=0).cpu().to(torch.float32).numpy()
            
            target_info = ctx['orig_target'].copy()
            target_info['target_code'] = ctx['target_code']
            target_info['context_code'] = ctx['context_code']
            
            embeddings.append(mean_pooled)
            valid_contexts.append(target_info)
            
    return np.array(embeddings), valid_contexts

import multiprocessing
import concurrent.futures

def process_benchmark(bench_name, bench_dir):
    b_path = os.path.join(bench_dir, bench_name)
    slice_file = os.path.join(b_path, "slice_dfg.txt")
    download_sh = os.path.join(b_path, "download.sh")
    
    if not os.path.exists(slice_file) or not os.path.exists(download_sh):
        return bench_name, None, None
        
    targets = []
    with open(slice_file, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 2:
                file_line = parts[1]
                score = parts[0]
                if ':' in file_line:
                    filename, lineno = file_line.split(':')
                    targets.append({
                        'project': bench_name,
                        'filename': filename, 
                        'lineno': int(lineno), 
                        'score': score
                    })
                    
    if not targets:
        return bench_name, None, None
        
    with CachedSourceDir(download_sh, bench_dir, bench_name) as temp_src_dir:
        contexts = extract_context(temp_src_dir, targets)
        
    return bench_name, targets, contexts

def main():
    parser = argparse.ArgumentParser(description="Global Semantic-Aware Block Classification")
    parser.add_argument("--bench_dir", required=True, help="Path to benchmarks directory")
    # Leave these arguments so manage.py doesn't crash if they are provided, but we ignore them
    parser.add_argument("--slice_file", required=False, help="Ignored")
    parser.add_argument("--out_file", required=False, help="Ignored")
    parser.add_argument("--src_dir", required=False, help="Ignored")
    
    args = parser.parse_args()
    
    bench_dir = os.path.abspath(args.bench_dir)
    
    max_workers = multiprocessing.cpu_count()
    torch.set_num_threads(max_workers)
    
    # Set up models directory and cache file paths
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'models')
    os.makedirs(models_dir, exist_ok=True)
    embed_file = os.path.join(models_dir, 'raw_embeddings.npy')
    ctx_file = os.path.join(models_dir, 'valid_contexts.pkl')
    
    if os.path.exists(embed_file) and os.path.exists(ctx_file):
        print(f"Found cached embeddings in {models_dir}. Loading from disk...")
        X = np.load(embed_file)
        all_valid_contexts = joblib.load(ctx_file)
        print(f"Loaded {X.shape[0]} embeddings.")
    else:
        # Step 1: Global Pooling
        print(f"Step 1: Global Pooling across all benchmarks (utilizing {max_workers} cores)...")
        if not os.path.isdir(bench_dir):
            print(f"Error: {bench_dir} is not a directory.")
            sys.exit(1)
            
        benchmark_dirs = sorted([d for d in os.listdir(bench_dir) if os.path.isdir(os.path.join(bench_dir, d))])
        
        all_embeddings = []
        all_valid_contexts = []
        
        all_contexts = []
        with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_benchmark, bench_name, bench_dir): bench_name for bench_name in benchmark_dirs}
            
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Extracting Contexts"):
                bench_name = futures[future]
                try:
                    name, targets, contexts = future.result()
                    if contexts:
                        all_contexts.extend(contexts)
                    else:
                        tqdm.write(f"Skipped {name} (no valid targets or files)")
                except Exception as e:
                    tqdm.write(f"Error processing {bench_name}: {e}")
                    
        if not all_contexts:
            print("No contexts collected. Exiting.")
            return
            
        print(f"\nComputing embeddings for {len(all_contexts)} total contexts...")
        embeddings, v_ctxs = get_target_embeddings(all_contexts)
        if len(embeddings) > 0:
            all_embeddings.append(embeddings)
            all_valid_contexts.extend(v_ctxs)
                
        if not all_embeddings:
            print("No embeddings collected. Exiting.")
            return
            
        X = np.vstack(all_embeddings)
        print(f"Total valid embeddings collected: {X.shape[0]} from {len(all_valid_contexts)} contexts.")
        
        print("Saving raw embeddings and contexts to disk...")
        np.save(embed_file, X)
        joblib.dump(all_valid_contexts, ctx_file)
    
    # Step 2: Global Fitting & Labeling
    print("Step 2: Global Fitting & Labeling...")
    
    # Pipeline A (K-Means)
    print("  -> Pipeline A: UMAP(16d) + K-Means(16)")
    n_components_kmeans = min(16, X.shape[0] - 1) if X.shape[0] > 16 else max(2, X.shape[0] - 1)
    umap_kmeans = umap.UMAP(n_components=n_components_kmeans, n_neighbors=50, min_dist=0.0, random_state=42)
    X_umap_kmeans = umap_kmeans.fit_transform(X)
    
    n_clusters = min(16, X.shape[0])
    kmeans = KMeans(n_clusters=n_clusters, random_state=42)
    labels_kmeans = kmeans.fit_predict(X_umap_kmeans)
    
    if X_umap_kmeans.shape[0] > 1:
        sample_size = 10000 if X_umap_kmeans.shape[0] > 10000 else X_umap_kmeans.shape[0]
        score_kmeans = silhouette_score(X_umap_kmeans, labels_kmeans, sample_size=sample_size, random_state=42)
        print(f"     [Metrics] KMeans Silhouette Score (16D): {score_kmeans:.4f}")
    
    # Pipeline B (HDBSCAN)
    print("  -> Pipeline B: UMAP(10d) + HDBSCAN")
    n_components_hdbscan = min(10, X.shape[0] - 1) if X.shape[0] > 10 else max(2, X.shape[0] - 1)
    umap_hdbscan = umap.UMAP(n_components=n_components_hdbscan, n_neighbors=50, min_dist=0.0, random_state=42)
    X_umap_hdbscan = umap_hdbscan.fit_transform(X)
    
    hdbscan = HDBSCAN(min_cluster_size=200, min_samples=30, metric='euclidean')
    labels_hdbscan = hdbscan.fit_predict(X_umap_hdbscan)
    
    core_mask = labels_hdbscan != -1
    if np.sum(core_mask) > 1 and len(np.unique(labels_hdbscan[core_mask])) > 1:
        X_core = X_umap_hdbscan[core_mask]
        labels_core = labels_hdbscan[core_mask]
        sample_size = 10000 if X_core.shape[0] > 10000 else X_core.shape[0]
        score_hdbscan = silhouette_score(X_core, labels_core, sample_size=sample_size, random_state=42)
        print(f"     [Metrics] HDBSCAN Silhouette Score (10D, Core Only): {score_hdbscan:.4f}")
        print(f"     [Stats] HDBSCAN Core Points: {np.sum(core_mask)}/{X.shape[0]}, Clusters: {len(np.unique(labels_core))}")
    
    # Step 3: Model Serialization
    print("Step 3: Model Serialization...")
    # models_dir is already created
    
    joblib.dump(umap_kmeans, os.path.join(models_dir, 'umap_kmeans.pkl'))
    joblib.dump(kmeans, os.path.join(models_dir, 'kmeans.pkl'))
    joblib.dump(umap_hdbscan, os.path.join(models_dir, 'umap_hdbscan.pkl'))
    joblib.dump(hdbscan, os.path.join(models_dir, 'hdbscan.pkl'))
    print(f"Models saved to {models_dir}")
    
    # Step 4: Split & Distribute
    print("Step 4: Split & Distribute...")
    project_groups = {}
    for i, target in enumerate(all_valid_contexts):
        proj = target['project']
        if proj not in project_groups:
            project_groups[proj] = []
        project_groups[proj].append({
            'filename': target['filename'],
            'lineno': target['lineno'],
            'kmeans_label': labels_kmeans[i],
            'hdbscan_label': labels_hdbscan[i]
        })
        
    for proj, items in project_groups.items():
        proj_dir = os.path.join(bench_dir, proj)
        
        out_kmeans = os.path.join(proj_dir, 'cluster_map_kmeans.txt')
        with open(out_kmeans, 'w') as f:
            for item in items:
                f.write(f"{item['kmeans_label']} {item['filename']}:{item['lineno']}\n")
                
        out_hdbscan = os.path.join(proj_dir, 'cluster_map_hdbscan.txt')
        with open(out_hdbscan, 'w') as f:
            for item in items:
                f.write(f"{item['hdbscan_label']} {item['filename']}:{item['lineno']}\n")
                
    print("\nGlobal classification complete!")

if __name__ == "__main__":
    main()
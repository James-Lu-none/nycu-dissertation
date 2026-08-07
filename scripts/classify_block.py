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
import itertools
import matplotlib.pyplot as plt
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
            src_str = src_bytes.decode('utf-8', errors='ignore')
            file_cache[filename] = {'bytes': src_bytes, 'tree': tree, 'lines': src_str.split('\n')}
            
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
        context_code = '\n'.join(extracted_lines)
        
        target_local_idx = line_idx - start_line
        
        pre_text = '\n'.join(extracted_lines[:target_local_idx])
        if pre_text:
            pre_text += '\n'
        
        target_line_text = extracted_lines[target_local_idx]
        
        start_char_idx = len(pre_text)
        end_char_idx = start_char_idx + len(target_line_text)
        
        contexts.append({
            'context_code': context_code,
            'start_char': start_char_idx,
            'end_char': end_char_idx,
            'orig_target': t,
            'target_code': target_line_text.strip()
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
    # print("  -> Pipeline A: UMAP(16d) + K-Means(16)")
    # n_components_kmeans = min(16, X.shape[0] - 1) if X.shape[0] > 16 else max(2, X.shape[0] - 1)
    # umap_kmeans = umap.UMAP(n_components=n_components_kmeans, n_neighbors=50, min_dist=0.0, random_state=42)
    # X_umap_kmeans = umap_kmeans.fit_transform(X)
    # 
    # n_clusters = min(16, X.shape[0])
    # kmeans = KMeans(n_clusters=n_clusters, random_state=42)
    # labels_kmeans = kmeans.fit_predict(X_umap_kmeans)
    # 
    # if X_umap_kmeans.shape[0] > 1:
    #     sample_size = 10000 if X_umap_kmeans.shape[0] > 10000 else X_umap_kmeans.shape[0]
    #     score_kmeans = silhouette_score(X_umap_kmeans, labels_kmeans, sample_size=sample_size, random_state=42)
    #     print(f"     [Metrics] KMeans Silhouette Score (16D): {score_kmeans:.4f}")
    
    # Pipeline B (HDBSCAN) - Grid Search
    print("Step 2/3: Grid Search for UMAP + HDBSCAN & Serialization/Visualization...")
    # 恢復為原本有 0.54 高分的 10 維空間，降維過度會導致點之間互相重疊，破壞輪廓係數
    n_components = min(10, X.shape[0] - 1) if X.shape[0] > 10 else max(2, X.shape[0] - 1)
    
    # 預設 Grid Search 參數範圍 (新增 n_components 以比較 2D 直觀分群 vs 10D 空間分群)
    param_grid = {
        'n_components': [2, 10],
        'n_neighbors': [50],
        'min_cluster_size': [200, 500],
        'min_samples': [30]
    }
    
    keys = list(param_grid.keys())
    combinations = list(itertools.product(*(param_grid[k] for k in keys)))
    
    best_score = -float('inf')
    best_labels = None
    best_params = None
    
    for combo in combinations:
        params = dict(zip(keys, combo))
        nc = params['n_components']
        nn = params['n_neighbors']
        mcs = params['min_cluster_size']
        ms = params['min_samples']
        
        print(f"\n--- Evaluating UMAP(nc={nc}, nn={nn}) + HDBSCAN(mcs={mcs}, ms={ms}) ---")
        
        umap_hdbscan = umap.UMAP(n_components=nc, n_neighbors=nn, min_dist=0.0, random_state=42)
        X_umap_hdbscan = umap_hdbscan.fit_transform(X)
        
        hdbscan = HDBSCAN(min_cluster_size=mcs, min_samples=ms, metric='euclidean')
        labels_hdbscan = hdbscan.fit_predict(X_umap_hdbscan)
        
        core_mask = labels_hdbscan != -1
        score_hdbscan = -1
        if np.sum(core_mask) > 1 and len(np.unique(labels_hdbscan[core_mask])) > 1:
            X_core = X_umap_hdbscan[core_mask]
            labels_core = labels_hdbscan[core_mask]
            # 移除 sample_size 以計算完整的輪廓係數，避免隨機抽樣導致分數失準（可能變負數）
            score_hdbscan = silhouette_score(X_core, labels_core, random_state=42)
            print(f"     [Metrics] Silhouette Score (Core Only): {score_hdbscan:.4f}")
            print(f"     [Stats] Core Points: {np.sum(core_mask)}/{X.shape[0]}, Clusters: {len(np.unique(labels_core))}")
        
        if score_hdbscan > best_score:
            best_score = score_hdbscan
            best_labels = labels_hdbscan.copy()
            best_params = params.copy()
            print(f"     *** New Best Score! ***")
            
        # Serialize Model
        param_dir_name = f"umap{nc}d_nn{nn}_mcs{mcs}_ms{ms}"
        param_models_dir = os.path.join(models_dir, param_dir_name)
        os.makedirs(param_models_dir, exist_ok=True)
        
        joblib.dump(umap_hdbscan, os.path.join(param_models_dir, 'umap_hdbscan.pkl'))
        joblib.dump(hdbscan, os.path.join(param_models_dir, 'hdbscan.pkl'))
        
        # Visualization
        print("     [Visual] Generating cluster plot...")
        X_emb = umap_hdbscan.embedding_
        if X_emb is not None and X_emb.shape[0] > 1:
            plot_labels = labels_hdbscan.copy()
            if X_emb.shape[0] > 10000:
                np.random.seed(42)
                idx = np.random.choice(X_emb.shape[0], 10000, replace=False)
                X_emb_sub = X_emb[idx]
                plot_labels = plot_labels[idx]
            else:
                X_emb_sub = X_emb
                
            # 若原始已經是 2D，直接使用；若為 10D，才再透過 UMAP 降維畫圖
            if nc == 2:
                X_2d = X_emb_sub
            else:
                reducer_2d = umap.UMAP(n_components=2, n_neighbors=50, min_dist=0.0, n_jobs=-1, random_state=42)
                X_2d = reducer_2d.fit_transform(X_emb_sub)
            
            c_mask = plot_labels != -1
            n_mask = plot_labels == -1
            
            unique_h, counts_h = np.unique(labels_hdbscan, return_counts=True)
            count_dict_h = dict(zip(unique_h, counts_h))
            
            plt.figure(figsize=(12, 10))
            plt.scatter(X_2d[n_mask, 0], X_2d[n_mask, 1], c='lightgrey', s=1, alpha=0.3, label='Noise')
            scatter = plt.scatter(X_2d[c_mask, 0], X_2d[c_mask, 1], c=plot_labels[c_mask], cmap='tab20', s=2, alpha=0.6)
            
            plt.title(f'Global HDBSCAN Clusters | UMAP({nc}d, nn={nn}) | HDBSCAN(mcs={mcs}, ms={ms})\nSilhouette (Core): {score_hdbscan:.4f}')
            cbar = plt.colorbar(scatter, label='Cluster ID (Point Count)')
            unique_ids_h = sorted([k for k in count_dict_h.keys() if k != -1])
            cbar.set_ticks(unique_ids_h)
            cbar.ax.tick_params(labelsize=8)
            cbar.set_ticklabels([f"{k} ({count_dict_h[k]})" for k in unique_ids_h])
            
            noise_count = count_dict_h.get(-1, 0)
            plt.text(0.01, 0.01, f'Noise Points: {noise_count}', transform=plt.gca().transAxes, fontsize=10, bbox=dict(facecolor='white', alpha=0.8))
            
            plt.savefig(os.path.join(param_models_dir, 'global_hdbscan_clusters.png'), dpi=300, bbox_inches='tight')
            plt.close()
            
    print(f"\nGrid search completed. Best params: {best_params} with Score: {best_score:.4f}")

    # Step 4: Split & Distribute (Using Best Model)
    print(f"Step 4: Split & Distribute (Using Best Model: {best_params})...")
    project_groups = {}
    for i, target in enumerate(all_valid_contexts):
        proj = target['project']
        if proj not in project_groups:
            project_groups[proj] = []
        project_groups[proj].append({
            'filename': target['filename'],
            'lineno': target['lineno'],
            'target_code': target.get('target_code', ''),
            'context_code': target.get('context_code', ''),
            'hdbscan_label': best_labels[i]
        })
        
    for proj, items in project_groups.items():
        proj_dir = os.path.join(bench_dir, proj)
                
        # Write HDBSCAN outputs
        out_hdbscan_txt = os.path.join(proj_dir, 'cluster_map_hdbscan.txt')
        out_hdbscan_log = os.path.join(proj_dir, 'cluster_map_hdbscan.log')
        try:
            with open(out_hdbscan_txt, 'w') as f_txt, open(out_hdbscan_log, 'w') as f_log:
                f_log.write(f"--- HDBSCAN Clustering Results (Best Model: {best_params}) ---\n")
                for item in items:
                    f_txt.write(f"{item['hdbscan_label']} {item['filename']}:{item['lineno']}\n")
                    
                    ctx_lines = len(item['context_code'].split('\n')) if item['context_code'] else 0
                    ctx_chars = len(item['context_code'])
                    log_line = (f"Cluster {item['hdbscan_label']:2d} | {item['filename']}:{item['lineno']} | "
                                f"(Ctx Lines: {ctx_lines}, Chars: {ctx_chars}) | {item['target_code']}\n")
                    f_log.write(log_line)
        except PermissionError as e:
            print(f"     [Warning] Permission denied when writing to {proj_dir}. Skipping output for this benchmark.")
                
    print("\nGlobal classification complete!")

if __name__ == "__main__":
    main()
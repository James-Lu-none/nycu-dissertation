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
import csv
from joblib import Parallel, delayed
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
    # 為了減少 Noise，我們降低 min_samples (讓 HDBSCAN 更寬容)，並測試更小的 min_cluster_size
    param_grid = {
        'n_components': [5, 8, 10],           # 包含 5D, 有時候更低維度能凸顯群體
        'n_neighbors': [15, 30, 50, 100],     # 涵蓋從極端局部 (15) 到極大全域 (100)
        'min_dist': [0.0, 0.1, 0.25],         # 測試不同的緊密度
        'umap_metric': ['euclidean', 'cosine'], # 既然要放過夜，我們把 cosine 也加回來測看看
        'min_cluster_size': [100, 200, 300, 400, 500],
        'min_samples': [5, 10, 15, 20, 30]
    }
    
    keys = list(param_grid.keys())
    combinations = list(itertools.product(*(param_grid[k] for k in keys)))
    
    best_score = -float('inf')
    best_labels = None
    best_params = None
    best_umap_model = None
    best_hdbscan_model = None
    
    umap_keys = list(set((c[0], c[1], c[2], c[3]) for c in combinations))
    
    print(f"\n   -> [Parallel] Computing {len(umap_keys)} UMAP models concurrently...")
    
    def compute_umap(umap_key):
        nc, nn, md, u_metric = umap_key
        reducer = umap.UMAP(n_components=nc, n_neighbors=nn, min_dist=md, metric=u_metric, random_state=42)
        X_emb_local = reducer.fit_transform(X)
        
        if X_emb_local.shape[0] > 10000:
            np.random.seed(42)
            idx = np.random.choice(X_emb_local.shape[0], 10000, replace=False)
            X_emb_sub = X_emb_local[idx]
        else:
            idx = np.arange(X_emb_local.shape[0])
            X_emb_sub = X_emb_local
            
        if nc == 2:
            X_2d = X_emb_sub
        else:
            reducer_2d = umap.UMAP(n_components=2, n_neighbors=50, min_dist=0.0, n_jobs=1, random_state=42)
            X_2d = reducer_2d.fit_transform(X_emb_sub)
            
        return umap_key, (reducer, X_emb_local, X_2d, idx)

    # Run UMAP in parallel (n_jobs=6 to avoid Out-Of-Memory)
    umap_results = Parallel(n_jobs=6, verbose=10)(delayed(compute_umap)(key) for key in umap_keys)
    umap_cache = dict(umap_results)
    
    print(f"\n   -> [Parallel] Evaluating {len(combinations)} HDBSCAN models concurrently...")
    
    def evaluate_hdbscan_combo(combo, X_emb_local, X_2d, plot_idx):
        nc, nn, md, u_metric, mcs, ms = combo
        
        hdbscan_model = HDBSCAN(min_cluster_size=mcs, min_samples=ms, metric='euclidean')
        labels_hdbscan = hdbscan_model.fit_predict(X_emb_local)
        
        core_mask = labels_hdbscan != -1
        score_hdbscan = -1
        if np.sum(core_mask) > 1 and len(np.unique(labels_hdbscan[core_mask])) > 1:
            X_core = X_emb_local[core_mask]
            labels_core = labels_hdbscan[core_mask]
            score_hdbscan = silhouette_score(X_core, labels_core, random_state=42)
            
        param_dir_name = f"umap{nc}d_{u_metric[:3]}_nn{nn}_md{md}_mcs{mcs}_ms{ms}"
        param_models_dir = os.path.join(models_dir, param_dir_name)
        os.makedirs(param_models_dir, exist_ok=True)
        
        if score_hdbscan != -1:
            plot_labels = labels_hdbscan[plot_idx]
            c_mask = plot_labels != -1
            n_mask = plot_labels == -1
            
            unique_h, counts_h = np.unique(labels_hdbscan, return_counts=True)
            count_dict_h = dict(zip(unique_h, counts_h))
            
            plt.figure(figsize=(12, 10))
            plt.scatter(X_2d[n_mask, 0], X_2d[n_mask, 1], c='lightgrey', s=1, alpha=0.3, label='Noise')
            scatter = plt.scatter(X_2d[c_mask, 0], X_2d[c_mask, 1], c=plot_labels[c_mask], cmap='tab20', s=2, alpha=0.6)
            
            plt.title(f'Global HDBSCAN Clusters | UMAP({nc}d, {u_metric[:3]}, nn={nn}, md={md}) | HDBSCAN(mcs={mcs}, ms={ms})\nSilhouette (Core): {score_hdbscan:.4f}')
            cbar = plt.colorbar(scatter, label='Cluster ID (Point Count)')
            unique_ids_h = sorted([k for k in count_dict_h.keys() if k != -1])
            cbar.set_ticks(unique_ids_h)
            cbar.ax.tick_params(labelsize=8)
            cbar.set_ticklabels([f"{k} ({count_dict_h[k]})" for k in unique_ids_h])
            
            noise_count = count_dict_h.get(-1, 0)
            plt.text(0.01, 0.01, f'Noise Points: {noise_count}', transform=plt.gca().transAxes, fontsize=10, bbox=dict(facecolor='white', alpha=0.8))
            
            plt.savefig(os.path.join(param_models_dir, 'global_hdbscan_clusters.png'), dpi=300, bbox_inches='tight')
            plt.close()
            
            # Write metrics CSV
            metrics_csv_path = os.path.join(param_models_dir, 'metrics.csv')
            total_points = len(labels_hdbscan)
            core_points = np.sum(core_mask)
            core_ratio = core_points / total_points if total_points > 0 else 0
            clusters_count = len(unique_h) - (1 if -1 in unique_h else 0)
            
            with open(metrics_csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['n_components', 'n_neighbors', 'min_dist', 'umap_metric', 
                                 'min_cluster_size', 'min_samples', 'silhouette_score', 
                                 'total_points', 'core_points', 'core_ratio', 'clusters_count', 'noise_points'])
                writer.writerow([nc, nn, md, u_metric, mcs, ms, score_hdbscan, 
                                 total_points, core_points, core_ratio, clusters_count, noise_count])
            
        return score_hdbscan, labels_hdbscan, hdbscan_model, combo

    # Prepare jobs explicitly to avoid passing the UMAP reducer object to workers
    hdbscan_jobs = []
    for combo in combinations:
        umap_key = (combo[0], combo[1], combo[2], combo[3])
        reducer, X_emb_local, X_2d, plot_idx = umap_cache[umap_key]
        hdbscan_jobs.append((combo, X_emb_local, X_2d, plot_idx))

    # Run HDBSCAN in parallel (n_jobs=12 for higher concurrency)
    hdbscan_results = Parallel(n_jobs=12, verbose=10)(
        delayed(evaluate_hdbscan_combo)(combo, X_emb_local, X_2d, plot_idx) 
        for combo, X_emb_local, X_2d, plot_idx in hdbscan_jobs
    )
    
    # Collect results to find the best model
    for score, labels, hdbscan_model, combo in hdbscan_results:
        if score > best_score:
            best_score = score
            best_labels = labels
            best_params = dict(zip(keys, combo))
            best_umap_model = umap_cache[(combo[0], combo[1], combo[2], combo[3])][0]
            best_hdbscan_model = hdbscan_model
            print(f"     *** New Best Score! {best_score:.4f} with {best_params} ***")
            
    print(f"\nGrid search completed. Best params: {best_params} with Score: {best_score:.4f}")
    
    if best_params is None:
        print("No valid clusters found in any configuration.")
        return

    # Step 4: Serialize Best Model, Visualize & Export CSV
    print(f"\nStep 4: Serialize Best Model, Visualize & Export CSV...")
    
    nc = best_params['n_components']
    nn = best_params['n_neighbors']
    md = best_params['min_dist']
    u_metric = best_params.get('umap_metric', 'euclidean')
    mcs = best_params['min_cluster_size']
    ms = best_params['min_samples']
    
    param_dir_name = f"umap{nc}d_{u_metric[:3]}_nn{nn}_md{md}_mcs{mcs}_ms{ms}"
    param_models_dir = os.path.join(models_dir, param_dir_name)
    os.makedirs(param_models_dir, exist_ok=True)
    
    print(f"     [Serialize] Saving best models to {param_models_dir} ...")
    joblib.dump(best_umap_model, os.path.join(param_models_dir, 'umap_hdbscan.pkl'))
    joblib.dump(best_hdbscan_model, os.path.join(param_models_dir, 'hdbscan.pkl'))

    print("     [CSV] Exporting global clustering results to CSV...")
    csv_path = os.path.join(param_models_dir, 'cluster_results.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as f_csv:
        writer = csv.writer(f_csv)
        writer.writerow(['Project', 'Filename', 'LineNo', 'HDBSCAN_Label'])
        for i, target in enumerate(all_valid_contexts):
            writer.writerow([
                target['project'],
                target['filename'],
                target['lineno'],
                best_labels[i]
            ])
            
    print(f"\nGlobal classification complete! Best model saved in: {param_models_dir}")

    # Step 5: Aggregate all metrics.csv into a root summary.csv
    print(f"\nStep 5: Aggregating all metrics.csv into a root summary.csv...")
    summary_csv_path = os.path.join(models_dir, 'summary.csv')
    header_written = False
    
    with open(summary_csv_path, 'w', newline='', encoding='utf-8') as f_out:
        writer = csv.writer(f_out)
        
        for root, dirs, files in os.walk(models_dir):
            if 'metrics.csv' in files:
                m_csv_path = os.path.join(root, 'metrics.csv')
                try:
                    with open(m_csv_path, 'r', encoding='utf-8') as f_in:
                        reader = csv.reader(f_in)
                        header = next(reader)
                        if not header_written:
                            writer.writerow(header)
                            header_written = True
                        for row in reader:
                            writer.writerow(row)
                except Exception as e:
                    print(f"      [Warning] Could not read {m_csv_path}: {e}")
                    
    print(f"      Done! Summary written to {summary_csv_path}")

if __name__ == "__main__":
    main()
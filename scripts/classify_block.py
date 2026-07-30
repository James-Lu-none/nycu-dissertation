import os
import sys
import argparse
import tempfile
import subprocess
import shutil
import numpy as np
import torch
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from transformers import AutoTokenizer, AutoModel
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
import umap
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

def get_parser(filename):
    parser = Parser()
    if filename.endswith(".c") or filename.endswith(".h"):
        parser.language = Language(tree_sitter_c.language())
    else:
        parser.language = Language(tree_sitter_cpp.language())
    return parser

class TempSourceDir:
    def __init__(self, download_sh_path):
        self.download_sh_path = download_sh_path
        self.temp_dir = tempfile.TemporaryDirectory()
        
    def __enter__(self):
        cwd = self.temp_dir.name
        
        try:
            if os.path.exists(self.download_sh_path):
                print(f"Executing {self.download_sh_path} in temporary directory...")
                # Execute the script in the temp directory
                subprocess.check_call(["bash", os.path.abspath(self.download_sh_path)], cwd=cwd)
            else:
                print(f"Error: download script not found at {self.download_sh_path}")
                sys.exit(1)
                
        except subprocess.CalledProcessError as e:
            print(f"Error executing download.sh: {e}")
            sys.exit(1)
            
        # The src is expected to be placed within the cwd by download.sh
        # Check if there is a 'src' directory created, if not we just use cwd
        src_path = os.path.join(cwd, "src")
        if os.path.isdir(src_path):
            return src_path
        return cwd

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.temp_dir.cleanup()


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
    
    # Pre-parse files
    file_cache = {}
    for t in targets:
        filename = t['filename']
        lineno = t['lineno']
        
        if filename not in file_cache:
            filepath = None
            for root, _, files in os.walk(src_dir):
                if filename in files:
                    filepath = os.path.join(root, filename)
                    break
            if not filepath:
                print(f"Warning: File {filename} not found in {src_dir}")
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
        
        # lineno is 1-indexed, tree-sitter uses 0-indexed for start_point[0]
        line_idx = lineno - 1
        if line_idx >= len(lines):
            contexts.append(None)
            continue
            
        func_node = find_function_node(tree.root_node, line_idx)
        
        if func_node:
            start_line = func_node.start_point[0]
            end_line = func_node.end_point[0]
        else:
            # Fallback to simple window if not in a function
            start_line = max(0, line_idx - 50)
            end_line = min(len(lines) - 1, line_idx + 50)
            
        # Truncate if > 1000 lines
        if end_line - start_line > 1000:
            start_line = max(0, line_idx - 500)
            end_line = min(len(lines) - 1, line_idx + 500)
            
        # Extract code text
        extracted_lines = lines[start_line:end_line+1]
        context_code = b'\n'.join(extracted_lines).decode('utf-8', errors='ignore')
        
        # Calculate offset in the extracted string for the target line
        # The target line is at (line_idx - start_line) index in extracted_lines
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

def get_target_embeddings(contexts, model_name="jinaai/jina-embeddings-v2-base-code"):
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    model = AutoModel.from_pretrained(model_name, trust_remote_code=True)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    
    embeddings = []
    valid_contexts = []
    
    for ctx in contexts:
        if not ctx:
            continue
            
        context_code = ctx['context_code']
        start_char = ctx['start_char']
        end_char = ctx['end_char']
        
        encoded = tokenizer(
            context_code,
            return_tensors="pt",
            return_offsets_mapping=True,
            truncation=True,
            max_length=8192
        )
        
        offsets = encoded['offset_mapping'][0].numpy()
        input_ids = encoded['input_ids'].to(device)
        attention_mask = encoded['attention_mask'].to(device)
        
        target_token_indices = []
        for idx, (start_c, end_c) in enumerate(offsets):
            if start_c == end_c == 0:
                continue # special tokens
            # If the token overlaps with the target line character range
            if not (end_c <= start_char or start_c >= end_char):
                target_token_indices.append(idx)
                
        if not target_token_indices:
            print(f"Warning: Could not align tokens for {ctx['orig_target']}")
            continue
            
        with torch.no_grad():
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            
        # shape: (1, seq_len, hidden_size)
        last_hidden_state = outputs.last_hidden_state[0]
        
        target_states = last_hidden_state[target_token_indices]
        mean_pooled = target_states.mean(dim=0).cpu().numpy()
        
        target_info = ctx['orig_target'].copy()
        target_info['target_code'] = ctx['target_code']
        target_info['context_code'] = ctx['context_code']
        target_info['context_lines'] = len(ctx['context_code'].split('\n'))
        target_info['context_chars'] = len(ctx['context_code'])
        
        embeddings.append(mean_pooled)
        valid_contexts.append(target_info)
        
    return np.array(embeddings), valid_contexts

def cluster_embeddings(embeddings, valid_targets, out_file):
    # PCA to 32 dims for clustering
    # UMAP to 10 dims for clustering (if enough samples)
    if len(embeddings) > 10:
        reducer_10d = umap.UMAP(n_components=10, random_state=42)
        reduced = reducer_10d.fit_transform(embeddings)
    else:
        reduced = embeddings
        
    # UMAP to 2 dims for visualization
    if len(embeddings) > 2:
        reducer_2d = umap.UMAP(n_components=2, random_state=42)
        reduced_2d = reducer_2d.fit_transform(embeddings)
    else:
        from sklearn.decomposition import PCA
        pca_2d = PCA(n_components=2)
        reduced_2d = pca_2d.fit_transform(embeddings)
        
    from sklearn.cluster import HDBSCAN
    min_cluster_size = max(2, min(5, len(embeddings) // 10))
    if len(embeddings) < 2:
        labels = np.zeros(len(embeddings), dtype=int)
    else:
        hdbscan = HDBSCAN(min_cluster_size=min_cluster_size, metric='euclidean')
        labels = hdbscan.fit_predict(reduced)
        
    # Shift labels: Noise (-1) becomes 0. Clusters (0,1..) become 1,2..
    best_labels = [lbl + 1 for lbl in labels]
    best_k = len(set(best_labels))
    
    log_file = out_file.replace('.txt', '.log')
    with open(log_file, 'w') as lf:
        def log_print(msg):
            print(msg)
            lf.write(msg + '\n')

        log_print("\n--- Clustering Evaluation ---")
        log_print(f"Using HDBSCAN with min_cluster_size={min_cluster_size}")
        log_print(f"Found {best_k} clusters (including noise as Cluster 0)")
        
        log_print("\n--- Clustering Results ---")
        csv_file = out_file.replace('cluster_map.txt', 'semantic_map.csv')
        if csv_file == out_file: # Fallback if out_file is not cluster_map.txt
            csv_file = out_file + ".csv"
            
        with open(out_file, 'w') as f, open(csv_file, 'w') as csvf:
            for target, label in zip(valid_targets, best_labels):
                log_print(f"Cluster {label:2d} | {target['filename']}:{target['lineno']} (L:{target.get('context_lines', 0)}, C:{target.get('context_chars', 0)}) | {target.get('target_code', '')}")
                f.write(f"{label} {target['filename']}:{target['lineno']}\n")
                
                # Format: s_idx,score,targ_line,mapped,semantic_type
                s_idx = target.get('s_idx', 0)
                score = target.get('score', 0)
                csvf.write(f"{s_idx},{score},{target['filename']}:{target['lineno']},mapped,{label}\n")
                
        log_print("\n--- Full Target Contexts ---")
        for target, label in zip(valid_targets, best_labels):
            lf.write(f"\n[{target['filename']}:{target['lineno']}] Cluster {label}\n")
            lf.write("-" * 40 + "\n")
            lf.write(target.get('context_code', '') + "\n")
            lf.write("-" * 40 + "\n")
            
        log_print(f"\nCluster map written to {out_file}")
        log_print(f"Semantic CSV written to {csv_file}")
        log_print(f"Detailed logs written to {log_file}")

    # Visualization
    plt.figure(figsize=(10, 8))
    scatter = plt.scatter(reduced_2d[:, 0], reduced_2d[:, 1], c=best_labels, cmap='tab20', alpha=0.7, edgecolors='k')
    plt.colorbar(scatter, label='Cluster ID (0=Noise)')
    plt.title('2D UMAP Visualization of Basic Block Embeddings')
    plt.xlabel('UMAP Component 1')
    plt.ylabel('UMAP Component 2')
    
    # Add parameters as text on the plot
    param_text = (
        f"Model: Jina-Embeddings-v2-Base-Code\n"
        f"Algorithm: HDBSCAN\n"
        f"Min Cluster Size: {min_cluster_size}\n"
        f"Found Clusters: {best_k}\n"
        f"Total Samples: {len(embeddings)}"
    )
    plt.text(0.05, 0.95, param_text, transform=plt.gca().transAxes, fontsize=10,
             verticalalignment='top', bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
             
    vis_file = out_file.replace('.txt', '_vis.png')
    plt.savefig(vis_file, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Visualization saved to {vis_file}")

def run_pipeline(args, src_dir, targets):
    print("Extracting contexts...")
    contexts = extract_context(src_dir, targets)
    
    print("Computing embeddings...")
    embeddings, valid_targets = get_target_embeddings(contexts)
    
    if len(embeddings) == 0:
        print("Error: No valid embeddings generated.")
        return
        
    print(f"Generated embeddings for {len(embeddings)} targets. Starting clustering...")
    cluster_embeddings(embeddings, valid_targets, args.out_file)

def main():
    parser = argparse.ArgumentParser(description="Semantic-Aware Block Classification")
    parser.add_argument("--slice_file", required=True, help="Path to slice_dfg.txt")
    parser.add_argument("--src_dir", required=False, help="Path to source directory (optional if download.sh is present)")
    parser.add_argument("--out_file", default="cluster_map.txt", help="Output cluster map file")
    
    args = parser.parse_args()
    
    targets = []
    with open(args.slice_file, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 2:
                file_line = parts[1]
                score = parts[0]
                if ':' in file_line:
                    filename, lineno = file_line.split(':')
                    targets.append({'filename': filename, 'lineno': int(lineno), 'score': score, 's_idx': len(targets)})
                    
    print(f"Parsed {len(targets)} targets from {args.slice_file}")
    
    src_dir = args.src_dir
    # Auto-detect download.sh file in the same directory as slice_file
    download_sh = os.path.join(os.path.dirname(os.path.abspath(args.slice_file)), 'download.sh')
    
    # If src_dir is not provided or missing, fallback to dynamic fetching via download.sh
    if not src_dir or not os.path.exists(src_dir):
        if os.path.exists(download_sh):
            print(f"Source directory not found. Dynamically fetching via {download_sh}...")
            with TempSourceDir(download_sh) as temp_src_dir:
                run_pipeline(args, temp_src_dir, targets)
            return
        else:
            print(f"Error: valid src_dir not provided and {download_sh} not found.")
            sys.exit(1)
            
    # Otherwise just use the provided src_dir
    run_pipeline(args, src_dir, targets)

if __name__ == "__main__":
    main()
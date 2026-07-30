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

def load_env_vars(env_path):
    env_vars = {}
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, val = line.split('=', 1)
                    env_vars[key.strip()] = val.strip('\'"')
    return env_vars

class TempSourceDir:
    def __init__(self, env_vars):
        self.env_vars = env_vars
        self.temp_dir = tempfile.TemporaryDirectory()
        
    def __enter__(self):
        cwd = self.temp_dir.name
        tar_url = self.env_vars.get('SRC_TAR_URL')
        git_repo = self.env_vars.get('GIT_REPO')
        git_branch = self.env_vars.get('GIT_BRANCH')
        patch_cmd = self.env_vars.get('SRC_PATCH_CMD')
        
        try:
            if tar_url:
                print(f"Downloading {tar_url} to temporary directory...")
                tar_name = "src.tar.gz"
                subprocess.check_call(["wget", "-q", "-O", tar_name, tar_url], cwd=cwd)
                subprocess.check_call(["tar", "-xzf", tar_name], cwd=cwd)
                os.remove(os.path.join(cwd, tar_name))
            elif git_repo:
                print(f"Cloning {git_repo} to temporary directory...")
                subprocess.check_call(["git", "clone", git_repo, "src"], cwd=cwd)
                if git_branch:
                    subprocess.check_call(["git", "checkout", git_branch], cwd=os.path.join(cwd, "src"))
            
            if patch_cmd:
                print(f"Applying patches: {patch_cmd}")
                subprocess.check_call(patch_cmd, shell=True, cwd=cwd)
                
        except subprocess.CalledProcessError as e:
            print(f"Error fetching source: {e}")
            sys.exit(1)
            
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
        
        embeddings.append(mean_pooled)
        valid_contexts.append(target_info)
        
    return np.array(embeddings), valid_contexts

def cluster_embeddings(embeddings, valid_targets, out_file):
    # PCA to 32 dims for clustering
    if len(embeddings) > 32:
        pca = PCA(n_components=32)
        reduced = pca.fit_transform(embeddings)
    else:
        reduced = embeddings
        
    # PCA to 2 dims for visualization
    pca_2d = PCA(n_components=2)
    reduced_2d = pca_2d.fit_transform(embeddings)
        
    best_k = -1
    best_score = -1
    best_labels = None
    best_kmeans = None
    
    max_k = min(15, len(embeddings) - 1)
    min_k = min(5, max_k)
    
    log_file = out_file.replace('.txt', '.log')
    with open(log_file, 'w') as lf:
        def log_print(msg):
            print(msg)
            lf.write(msg + '\n')

        if min_k < 2:
            best_k = 1
            best_labels = np.zeros(len(embeddings), dtype=int)
            log_print("Only 1 cluster due to small number of samples.")
        else:
            log_print("\n--- Clustering Evaluation ---")
            for k in range(min_k, max_k + 1):
                kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
                labels = kmeans.fit_predict(reduced)
                score = silhouette_score(reduced, labels)
                log_print(f"K={k}, Silhouette Score={score:.4f}, Iterations={kmeans.n_iter_}")
                if score > best_score:
                    best_score = score
                    best_k = k
                    best_labels = labels
                    best_kmeans = kmeans
                
        log_print(f"\nSelected best K={best_k} with Silhouette Score={best_score:.4f}")
        
        log_print("\n--- Clustering Results ---")
        with open(out_file, 'w') as f:
            for target, label in zip(valid_targets, best_labels):
                log_print(f"Cluster {label:2d} | {target['filename']}:{target['lineno']} | {target['target_code']}")
                f.write(f"{label} {target['filename']}:{target['lineno']}\n")
        log_print(f"\nCluster map written to {out_file}")
        log_print(f"Detailed logs written to {log_file}")

    # Visualization
    plt.figure(figsize=(10, 8))
    scatter = plt.scatter(reduced_2d[:, 0], reduced_2d[:, 1], c=best_labels, cmap='tab20', alpha=0.7, edgecolors='k')
    plt.colorbar(scatter, label='Cluster ID')
    plt.title('2D Visualization of Basic Block Embeddings')
    plt.xlabel('PCA Component 1')
    plt.ylabel('PCA Component 2')
    
    # Add parameters as text on the plot
    param_text = (
        f"Model: Jina-Embeddings-v2-Base-Code\n"
        f"K-Means k: {best_k}\n"
        f"Silhouette Score: {best_score:.4f}\n"
        f"Iterations: {best_kmeans.n_iter_ if best_kmeans else 'N/A'}\n"
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
    parser.add_argument("--src_dir", required=False, help="Path to source directory (optional if .env config is present)")
    parser.add_argument("--out_file", default="cluster_map.txt", help="Output cluster map file")
    
    args = parser.parse_args()
    
    targets = []
    with open(args.slice_file, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 2:
                file_line = parts[1]
                if ':' in file_line:
                    filename, lineno = file_line.split(':')
                    targets.append({'filename': filename, 'lineno': int(lineno)})
                    
    print(f"Parsed {len(targets)} targets from {args.slice_file}")
    
    src_dir = args.src_dir
    # Auto-detect .env file in the same directory as slice_file
    env_file = os.path.join(os.path.dirname(os.path.abspath(args.slice_file)), '.env')
    env_vars = load_env_vars(env_file)
    
    # If src_dir is not provided or missing, fallback to dynamic fetching via .env
    if not src_dir or not os.path.exists(src_dir):
        if 'SRC_TAR_URL' in env_vars or 'GIT_REPO' in env_vars:
            print(f"Source directory not found. Dynamically fetching via .env configuration...")
            with TempSourceDir(env_vars) as temp_src_dir:
                run_pipeline(args, temp_src_dir, targets)
            return
        else:
            print("Error: valid src_dir not provided and no SRC_TAR_URL/GIT_REPO found in .env file.")
            sys.exit(1)
            
    # Otherwise just use the provided src_dir
    run_pipeline(args, src_dir, targets)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import sys
import os
import re
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

def parse_matrix(filepath):
    if not os.path.exists(filepath):
        return None
    try:
        # skip first line header
        return np.loadtxt(filepath, skiprows=1)
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 matrix_plot.py <cve>")
        sys.exit(1)
        
    cve = sys.argv[1]
    print(f"[*] Target CVE: {cve}")
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    cve_dir = os.path.join(root_dir, "artifact", cve)
    
    print(f"[*] Checking directory: {cve_dir}")
    if not os.path.exists(cve_dir):
        print(f"[-] Artifact directory for {cve} not found.")
        sys.exit(1)
        
    sessions = []
    for d in os.listdir(cve_dir):
        if os.path.isdir(os.path.join(cve_dir, d)) and d not in ["plot", "TTE_check"]:
            sessions.append(d)
            
    if not sessions:
        print("[-] No sessions found.")
        sys.exit(1)
        
    print(f"[*] Found {len(sessions)} sessions: {sessions}")
        
    def sort_session_key(x):
        ts_match = re.search(r'_(\d{8}_\d{6})$', x)
        return ts_match.group(1) if ts_match else ""
        
    sessions.sort(key=sort_session_key)
    latest_session = sessions[-1]
    print(f"[*] Selected latest session: {latest_session}")
    session_dir = os.path.join(cve_dir, latest_session)
    
    plot_dir = os.path.join(session_dir, "plot")
    os.makedirs(plot_dir, exist_ok=True)
    print(f"[*] Output plot directory: {plot_dir}")
    
    methods = [d for d in os.listdir(session_dir) if os.path.isdir(os.path.join(session_dir, d)) and d not in ["plot", "TTE_check"]]
    print(f"[*] Methods found: {methods}")
    
    matrix_files = [
        "mut_prob_matrix_600s.txt",
        "mut_prob_matrix.txt",
        "semantic_prob_matrix_600s.txt",
        "semantic_prob_matrix.txt"
    ]
    
    for filename in matrix_files:
        print(f"\n[+] Processing matrix file target: {filename}")
        method_averages = {}
        
        for method in methods:
            print(f"  -> Processing method: {method}")
            method_dir = os.path.join(session_dir, method)
            matrices = []
            
            for trial in os.listdir(method_dir):
                trial_dir = os.path.join(method_dir, trial)
                if not os.path.isdir(trial_dir):
                    continue
                filepath = os.path.join(trial_dir, filename)
                
                if os.path.exists(filepath):
                    print(f"    -> Loading trial: {trial} ({filepath})")
                    mat = parse_matrix(filepath)
                    if mat is not None:
                        matrices.append(mat)
                        print(f"      -> Successfully parsed matrix of shape {mat.shape}")
                    else:
                        print(f"      -> Failed to parse matrix.")
                else:
                    print(f"    -> File not found for trial {trial}: {filepath}")
            
            if matrices:
                avg_mat = np.mean(matrices, axis=0)
                method_averages[method] = avg_mat
                print(f"  -> Method {method} averaged over {len(matrices)} valid matrices.")
            else:
                print(f"  -> No valid matrices found for method {method}.")
        
        if method_averages:
            print(f"[*] Generating plot for {filename}...")
            plt.figure(figsize=(10, 8))
            
            num_methods = len(method_averages)
            fig, axes = plt.subplots(1, num_methods, figsize=(8 * num_methods, 6))
            if num_methods == 1:
                axes = [axes]
                
            for ax, (method, mat) in zip(axes, method_averages.items()):
                sns.heatmap(mat, cmap="viridis", ax=ax)
                ax.set_title(f"{method}")
                
            plt.suptitle(f"Average {filename} ({cve})")
            plt.tight_layout()
            
            out_path = os.path.join(plot_dir, f"{filename.replace('.txt', '')}.png")
            plt.savefig(out_path)
            plt.close(fig)
            plt.close('all')
            print(f"[*] Saved plot: {out_path}")
        else:
            print(f"[-] Skipping plot for {filename} as no data was collected across any method.")

if __name__ == "__main__":
    main()

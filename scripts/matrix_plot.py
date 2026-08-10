#!/usr/bin/env python3
import sys
import os
import re
import math
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict

def parse_matrix(filepath):
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
            
        if not lines: return None
        
        if "Semantic Type" in lines[0] or "Cluster " in lines[1]:
            # 3D Semantic Format
            matrix_3d = []
            current_cluster = -1
            current_cluster_matrix = []
            
            for line in lines[1:]:
                if "Cluster" in line and ":" in line:
                    header, data = line.split(":", 1)
                    cluster_str = header.split(",")[0].replace("Cluster", "").strip()
                    cluster_id = int(cluster_str)
                    
                    if cluster_id != current_cluster:
                        if current_cluster_matrix:
                            matrix_3d.append(np.array(current_cluster_matrix))
                        current_cluster = cluster_id
                        current_cluster_matrix = []
                        
                    row = [float(x) for x in data.strip().split()]
                    current_cluster_matrix.append(row)
                    
            if current_cluster_matrix:
                matrix_3d.append(np.array(current_cluster_matrix))
                
            return np.array(matrix_3d) if matrix_3d else None
        else:
            # 2D Mut Format
            return np.loadtxt(filepath, skiprows=1)
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 matrix_plot.py <cve>")
        sys.exit(1)
        
    cve = sys.argv[1]
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    cve_dir = os.path.join(root_dir, "artifact", cve)
    
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
        
    def sort_session_key(x):
        ts_match = re.search(r'_(\d{8}_\d{6})$', x)
        return ts_match.group(1) if ts_match else ""
        
    sessions.sort(key=sort_session_key)
    latest_session = sessions[-1]
    session_dir = os.path.join(cve_dir, latest_session)
    
    plot_dir = os.path.join(session_dir, "plot")
    os.makedirs(plot_dir, exist_ok=True)
    
    methods = [d for d in os.listdir(session_dir) if os.path.isdir(os.path.join(session_dir, d)) and d not in ["plot", "TTE_check"]]
    
    data = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))
    
    for method in methods:
        method_dir = os.path.join(session_dir, method)
        for trial in os.listdir(method_dir):
            trial_dir = os.path.join(method_dir, trial)
            if not os.path.isdir(trial_dir):
                continue
            
            for root, _, files in os.walk(trial_dir):
                for f in files:
                    m = re.match(r'(mut_prob|semantic_prob|finds_per_semantic_mut)_matrix(?:_(\d+)m|_600s)?\.txt', f)
                    if m:
                        mat_type = m.group(1)
                        mins_str = m.group(2)
                        if f.endswith('600s.txt'):
                            bucket = 10
                        elif mins_str is not None:
                            bucket = round(int(mins_str) / 10) * 10
                        else:
                            bucket = "final" # 給沒有後綴的矩陣一個標示
                            
                        filepath = os.path.join(root, f)
                        mat = parse_matrix(filepath)
                        if mat is not None:
                            data[mat_type][bucket][method][trial] = mat
                            
    for mat_type in list(data.keys()):
        def sort_bucket(b):
            return 999999 if b == "final" else int(b)
            
        for bucket in sorted(data[mat_type].keys(), key=sort_bucket):
            method_averages = {}
            method_stds = {}
            method_trials = {}
            
            for method, trial_matrices in data[mat_type][bucket].items():
                if trial_matrices:
                    mats = list(trial_matrices.values())
                    method_averages[method] = np.mean(mats, axis=0)
                    method_stds[method] = np.std(mats, axis=0)
                    method_trials[method] = trial_matrices
            
            if not method_averages:
                continue
                
            if bucket == "final":
                filename = f"{mat_type}_matrix_final"
            else:
                filename = f"{mat_type}_matrix_{bucket}m"
            num_methods = len(method_averages)
            
            sample_mat = method_averages[list(method_averages.keys())[0]]
            
            if sample_mat.ndim == 3:
                # --- 3D MATRIX PLOTTING (SEMANTIC) ---
                for method, avg_mat in method_averages.items():
                    num_clusters = avg_mat.shape[0]
                    cols = 5
                    rows = math.ceil(num_clusters / cols)
                    
                    # 1. Average
                    fig, axes = plt.subplots(rows, cols, figsize=(5 * cols, 4 * rows))
                    if num_clusters == 1: axes = np.array([axes])
                    axes = axes.flatten()
                    
                    for c in range(num_clusters):
                        sns.heatmap(avg_mat[c], cmap="viridis", ax=axes[c], cbar=False)
                        axes[c].set_title(f"Cluster {c}")
                    for c in range(num_clusters, len(axes)):
                        axes[c].set_visible(False)
                        
                    plt.suptitle(f"Average {filename} - {method} ({cve})", fontsize=16)
                    plt.tight_layout()
                    out_path = os.path.join(plot_dir, f"Average_{filename}_{method}.png")
                    plt.savefig(out_path)
                    print(f"Saving plot to {out_path}")
                    plt.close(fig)
                    
                    # 2. StdDev
                    std_mat = method_stds[method]
                    fig, axes = plt.subplots(rows, cols, figsize=(5 * cols, 4 * rows))
                    if num_clusters == 1: axes = np.array([axes])
                    axes = axes.flatten()
                    
                    for c in range(num_clusters):
                        sns.heatmap(std_mat[c], cmap="magma", ax=axes[c], cbar=False)
                        axes[c].set_title(f"Cluster {c}")
                    for c in range(num_clusters, len(axes)):
                        axes[c].set_visible(False)
                        
                    plt.suptitle(f"Std Dev {filename} - {method} ({cve})", fontsize=16)
                    plt.tight_layout()
                    out_path = os.path.join(plot_dir, f"StdDev_{filename}_{method}.png")
                    plt.savefig(out_path)
                    print(f"Saving plot to {out_path}")
                    plt.close(fig)
                
                # 3. All Trials (per trial)
                for method, trial_matrices in method_trials.items():
                    for trial, trial_mat in trial_matrices.items():
                        num_clusters = trial_mat.shape[0]
                        cols = 5
                        rows = math.ceil(num_clusters / cols)
                        
                        fig, axes = plt.subplots(rows, cols, figsize=(5 * cols, 4 * rows))
                        if num_clusters == 1: axes = np.array([axes])
                        axes = axes.flatten()
                        
                        for c in range(num_clusters):
                            sns.heatmap(trial_mat[c], cmap="viridis", ax=axes[c], cbar=False)
                            axes[c].set_title(f"Cluster {c}")
                        for c in range(num_clusters, len(axes)):
                            axes[c].set_visible(False)
                            
                        plt.suptitle(f"Trial {trial} {filename} - {method} ({cve})", fontsize=16)
                        plt.tight_layout()
                        out_path = os.path.join(plot_dir, f"Trial_{trial}_{filename}_{method}.png")
                        plt.savefig(out_path)
                        print(f"Saving plot to {out_path}")
                        plt.close(fig)

            else:
                # --- 2D MATRIX PLOTTING (MUT) ---
                # 1. Average
                fig, axes = plt.subplots(1, num_methods, figsize=(8 * num_methods, 6))
                if num_methods == 1: axes = [axes]
                for ax, method in zip(axes, method_averages.keys()):
                    sns.heatmap(method_averages[method], cmap="viridis", ax=ax)
                    ax.set_title(f"{method}")
                plt.suptitle(f"Average {filename} ({cve})")
                plt.tight_layout()
                out_path = os.path.join(plot_dir, f"Average_{filename}.png")
                plt.savefig(out_path)
                print(f"Saving plot to {out_path}")
                plt.close(fig)
                
                # 2. Std Dev
                fig, axes = plt.subplots(1, num_methods, figsize=(8 * num_methods, 6))
                if num_methods == 1: axes = [axes]
                for ax, method in zip(axes, method_stds.keys()):
                    sns.heatmap(method_stds[method], cmap="magma", ax=ax)
                    ax.set_title(f"{method}")
                plt.suptitle(f"Std Dev {filename} ({cve})")
                plt.tight_layout()
                out_path = os.path.join(plot_dir, f"StdDev_{filename}.png")
                plt.savefig(out_path)
                print(f"Saving plot to {out_path}")
                plt.close(fig)
                
                # 3. All Trials
                for method, trial_matrices in method_trials.items():
                    num_trials = len(trial_matrices)
                    if num_trials == 0: continue
                    
                    cols = 5
                    rows = math.ceil(num_trials / cols)
                    
                    fig, axes = plt.subplots(rows, cols, figsize=(6 * cols, 5 * rows))
                    if num_trials == 1: axes = np.array([axes])
                    axes = axes.flatten()
                    
                    sorted_trials = sorted(trial_matrices.keys())
                    
                    for idx, trial in enumerate(sorted_trials):
                        sns.heatmap(trial_matrices[trial], cmap="viridis", ax=axes[idx], cbar=False)
                        axes[idx].set_title(f"Trial: {trial}")
                        
                    for idx in range(num_trials, len(axes)):
                        axes[idx].set_visible(False)
                        
                    plt.suptitle(f"All Trials {filename} - {method} ({cve})", fontsize=16)
                    plt.tight_layout()
                    out_path = os.path.join(plot_dir, f"AllTrials_{filename}_{method}.png")
                    plt.savefig(out_path)
                    print(f"Saving plot to {out_path}")
                    plt.close(fig)
                    
            plt.close('all')

if __name__ == "__main__":
    main()

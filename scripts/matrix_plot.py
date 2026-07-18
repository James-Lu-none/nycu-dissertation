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
    # print(f"[*] Target CVE: {cve}")
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    cve_dir = os.path.join(root_dir, "artifact", cve)
    
    # print(f"[*] Checking directory: {cve_dir}")
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
        
    # print(f"[*] Found {len(sessions)} sessions: {sessions}")
        
    def sort_session_key(x):
        ts_match = re.search(r'_(\d{8}_\d{6})$', x)
        return ts_match.group(1) if ts_match else ""
        
    sessions.sort(key=sort_session_key)
    latest_session = sessions[-1]
    # print(f"[*] Selected latest session: {latest_session}")
    session_dir = os.path.join(cve_dir, latest_session)
    
    plot_dir = os.path.join(session_dir, "plot")
    os.makedirs(plot_dir, exist_ok=True)
    # print(f"[*] Output plot directory: {plot_dir}")
    
    methods = [d for d in os.listdir(session_dir) if os.path.isdir(os.path.join(session_dir, d)) and d not in ["plot", "TTE_check"]]
    # print(f"[*] Methods found: {methods}")
    
    # data[mat_type][bucket_mins][method][trial] = mat
    data = {"mut": defaultdict(lambda: defaultdict(dict)), "semantic": defaultdict(lambda: defaultdict(dict))}
    
    for method in methods:
        method_dir = os.path.join(session_dir, method)
        for trial in os.listdir(method_dir):
            trial_dir = os.path.join(method_dir, trial)
            if not os.path.isdir(trial_dir):
                continue
            
            for root, _, files in os.walk(trial_dir):
                for f in files:
                    m = re.match(r'(mut|semantic)_prob_matrix_(?:(\d+)m|600s)?\.txt', f)
                    if m:
                        mat_type = m.group(1)
                        mins_str = m.group(2)
                        if f.endswith('600s.txt'):
                            bucket = 10
                        elif mins_str is not None:
                            # round to nearest 10 mins
                            bucket = round(int(mins_str) / 10) * 10
                        else:
                            bucket = 30 # default old matrix
                            
                        filepath = os.path.join(root, f)
                        mat = parse_matrix(filepath)
                        if mat is not None:
                            data[mat_type][bucket][method][trial] = mat
                            
    for mat_type in data:
        for bucket in sorted(data[mat_type].keys()):
            method_averages = {}
            method_stds = {}
            method_trials = {}
            
            for method, trial_matrices in data[mat_type][bucket].items():
                if trial_matrices:
                    mats = list(trial_matrices.values())
                    method_averages[method] = np.mean(mats, axis=0)
                    method_stds[method] = np.std(mats, axis=0)
                    method_trials[method] = trial_matrices
                    # print(f"  -> {mat_type} @ {bucket}m: Method {method} loaded {len(mats)} valid matrices.")
            
            if not method_averages:
                continue
                
            filename = f"{mat_type}_prob_matrix_{bucket}m"
            num_methods = len(method_averages)
            
            # 1. Plot Average
            # print(f"[*] Generating Average plot for {filename}...")
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
            
            # 2. Plot Std Dev (Variance)
            # print(f"[*] Generating StdDev plot for {filename}...")
            fig, axes = plt.subplots(1, num_methods, figsize=(8 * num_methods, 6))
            if num_methods == 1: axes = [axes]
            for ax, method in zip(axes, method_stds.keys()):
                # Use 'magma' colormap for std deviation
                sns.heatmap(method_stds[method], cmap="magma", ax=ax)
                ax.set_title(f"{method}")
            plt.suptitle(f"Std Dev {filename} ({cve})")
            plt.tight_layout()
            out_path = os.path.join(plot_dir, f"StdDev_{filename}.png")
            plt.savefig(out_path)
            print(f"Saving plot to {out_path}")
            plt.close(fig)
            
            # 3. Plot Grid of all trials for each method individually
            for method, trial_matrices in method_trials.items():
                num_trials = len(trial_matrices)
                if num_trials == 0: continue
                
                # print(f"[*] Generating AllTrials plot for {filename} - {method}...")
                cols = 5
                rows = math.ceil(num_trials / cols)
                
                fig, axes = plt.subplots(rows, cols, figsize=(6 * cols, 5 * rows))
                if num_trials == 1: axes = np.array([axes])
                axes = axes.flatten()
                
                sorted_trials = sorted(trial_matrices.keys())
                
                for idx, trial in enumerate(sorted_trials):
                    # Hide cbar for individual small plots to save space
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

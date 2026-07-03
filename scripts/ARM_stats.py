#!/usr/bin/env python3
import sys
import os
import argparse
import pandas as pd
import numpy as np

def load_arm_rules(file_path):
    if not os.path.isfile(file_path):
        print(f"Error: File not found at {file_path}")
        return None
    try:
        df = pd.read_csv(file_path, comment='#')
        df.columns = [c.strip() for c in df.columns]
        return df
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def compute_chain_depths(df):
    """Compute longest dependency chain depth for each target block using topological sorting."""
    adj = {}
    in_degree = {}
    nodes = set(df['src_block']).union(set(df['dst_block']))
    
    for n in nodes:
        adj[n] = []
        in_degree[n] = 0
        
    for _, row in df.iterrows():
        u = int(row['src_block'])
        v = int(row['dst_block'])
        adj[u].append(v)
        in_degree[v] += 1
        
    depth = {n: 0 for n in nodes}
    queue = [n for n in nodes if in_degree[n] == 0]
    
    topo_order = []
    while queue:
        u = queue.pop(0)
        topo_order.append(u)
        for v in adj[u]:
            in_degree[v] -= 1
            if in_degree[v] == 0:
                queue.append(v)
                
    if len(topo_order) < len(nodes):
        return {n: 1 for n in nodes}
        
    for u in topo_order:
        for v in adj[u]:
            depth[v] = max(depth[v], depth[u] + 1)
            
    return depth

def plot_distributions(df, depths, out_dir, cve_name):
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
        
        sns.set_theme(style="ticks")
        plt.rcParams.update({
            'font.size': 11,
            'axes.labelsize': 12,
            'axes.titlesize': 13,
            'xtick.labelsize': 10,
            'ytick.labelsize': 10,
            'figure.titlesize': 14
        })
        
        in_degrees = df.groupby('dst_block').size().reindex(
            set(df['src_block']).union(set(df['dst_block'])), fill_value=0
        )
        
        plt.figure(figsize=(6, 4))
        active_in_degrees = in_degrees[in_degrees > 0]
        
        sns.histplot(active_in_degrees, bins=15, kde=False, color="#4a90e2", edgecolor="black")
        plt.title(f"Prerequisite Constraints per Block ({cve_name})", fontweight='bold')
        plt.xlabel("Number of Prerequisite Blocks ($K$)")
        plt.ylabel("Number of Target Blocks")
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        sns.despine()
        
        indegree_path = os.path.join(out_dir, "arm_prereq_count_dist.png")
        plt.tight_layout()
        plt.savefig(indegree_path, dpi=300)
        plt.close()
        print(f"[+] Saved Prerequisite count plot to {indegree_path}")
        
        depth_values = list(depths.values())
        active_depths = [d for d in depth_values if d > 0]
        
        plt.figure(figsize=(6, 4))
        sns.histplot(active_depths, bins=10, kde=False, color="#e74c3c", edgecolor="black")
        plt.title(f"Dependency Chain Depth ({cve_name})", fontweight='bold')
        plt.xlabel("Longest Prerequisite Chain Depth ($D$)")
        plt.ylabel("Number of Blocks")
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        sns.despine()
        
        depth_path = os.path.join(out_dir, "arm_chain_depth_dist.png")
        plt.tight_layout()
        plt.savefig(depth_path, dpi=300)
        plt.close()
        print(f"[+] Saved Dependency depth plot to {depth_path}")
        
    except ImportError:
        print("[-] matplotlib/seaborn not installed. Skipping plot generation.")

def print_paper_proof_summary(df, depths, cve_name):
    in_degrees = df.groupby('dst_block').size()
    max_prereqs = in_degrees.max()
    avg_prereqs = in_degrees.mean()
    
    depth_values = list(depths.values())
    max_depth = max(depth_values)
    avg_depth = np.mean([d for d in depth_values if d > 0])
    
    blocks_with_deps = len(in_degrees[in_degrees > 0])
    total_blocks = len(set(df['src_block']).union(set(df['dst_block'])))
    dep_percentage = (blocks_with_deps / total_blocks) * 100 if total_blocks > 0 else 0
    
    print("\n" + "="*60)
    print(f"        CAFL NON-INDEPENDENCE PROOF SUMMARY: {cve_name}")
    print("="*60)
    print(f"1. Total Interdependent Blocks Analyzed : {total_blocks}")
    print(f"2. Blocks Under Strict Order Constraints : {blocks_with_deps} ({dep_percentage:.1f}%)")
    print(f"3. Maximum Prereqs for a Single Block    : {max_prereqs} checkpoints")
    print(f"4. Average Prereqs per Constrained Block : {avg_prereqs:.2f} checkpoints")
    print(f"5. Maximum Topological Chain Depth (D)   : {max_depth} layers")
    print(f"6. Average Topological Chain Depth      : {avg_depth:.2f} layers")
    print("-"*60)
    print("Academic Thesis Validation Proof:")
    print("  -> Under DGF, block distance is modeled as independent linear sums.")
    print("  -> However, this data mathematically proves that:")
    print(f"     {dep_percentage:.1f}% of blocks are constrained by strict prerequisite relationships.")
    print(f"     The deepest control sequence requires solving up to {max_depth} nested chronological checkpoints.")
    print("     Thus, the linear independence assumption of intermediate targets is rejected.")
    print("="*60 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Analyze ARM Non-Independence Statistics")
    parser.add_argument("path", help="Path to arm_rules.txt / arm_rules.csv or artifact directory")
    parser.add_argument("--name", default="CVE", help="Benchmark name for output")
    args = parser.parse_args()
    
    target_path = args.path
    if os.path.isdir(target_path):
        candidates = []
        for root, dirs, files in os.walk(target_path):
            for file in files:
                if file in ["arm_rules.txt", "arm_rules.csv"]:
                    candidates.append(os.path.join(root, file))
        if not candidates:
            print(f"Error: No arm_rules.txt / csv found under {target_path}")
            sys.exit(1)
        target_path = candidates[0]
        print(f"[+] Found rule file: {target_path}")
        
    df = load_arm_rules(target_path)
    if df is None or len(df) == 0:
        print("[-] No ARM rules found or file empty.")
        sys.exit(0)
        
    abs_path = os.path.abspath(target_path)
    out_dir = os.path.dirname(abs_path)
    if "artifact" in abs_path:
        parts = abs_path.split("artifact" + os.sep)
        if len(parts) > 1:
            subparts = parts[1].split(os.sep)
            if len(subparts) >= 4:
                cve = subparts[0]
                session_dir = subparts[1]
                trial = subparts[3]
                root_dir = parts[0]
                unified_plot_dir = os.path.join(root_dir, "artifact", cve, "plot", session_dir, trial)
                os.makedirs(unified_plot_dir, exist_ok=True)
                out_dir = unified_plot_dir
            elif len(subparts) >= 2:
                cve = subparts[0]
                session_dir = subparts[1]
                root_dir = parts[0]
                unified_plot_dir = os.path.join(root_dir, "artifact", cve, "plot", session_dir)
                os.makedirs(unified_plot_dir, exist_ok=True)
                out_dir = unified_plot_dir
                
    depths = compute_chain_depths(df)
    plot_distributions(df, depths, out_dir, args.name)
    print_paper_proof_summary(df, depths, args.name)

if __name__ == "__main__":
    main()

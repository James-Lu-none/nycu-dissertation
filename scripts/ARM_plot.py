#!/usr/bin/env python3
import sys
import os
import argparse
import pandas as pd
import numpy as np

def load_arm_rules(file_path):
    """Load ARM rules CSV from file path."""
    if not os.path.isfile(file_path):
        print(f"Error: File not found at {file_path}")
        return None
    try:
        # Read CSV file; handles header src_block,dst_block,support,confidence
        df = pd.read_csv(file_path, comment='#')
        # Clean column names
        df.columns = [c.strip() for c in df.columns]
        return df
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def plot_heatmap(df, output_path, title="ARM Rule Adjacency Heatmap"):
    """Generate adjacency heatmap using matplotlib/seaborn."""
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
        
        max_block = max(df['src_block'].max(), df['dst_block'].max()) + 1
        matrix = np.zeros((max_block, max_block))
        
        for _, row in df.iterrows():
            u = int(row['src_block'])
            v = int(row['dst_block'])
            matrix[u, v] = row['support']
            
        plt.figure(figsize=(10, 8))
        sns.heatmap(matrix, cmap="viridis", cbar_kws={'label': 'Seed Support'}, robust=True)
        plt.title(title, fontsize=14, fontweight='bold')
        plt.xlabel("Target Block (Dst)", fontsize=12)
        plt.ylabel("Prerequisite Block (Src)", fontsize=12)
        plt.tight_layout()
        plt.savefig(output_path, dpi=300)
        plt.close()
        print(f"[+] Saved Heatmap to {output_path}")
    except ImportError:
        print("[-] matplotlib/seaborn not installed. Skipping heatmap generation.")

def main():
    parser = argparse.ArgumentParser(description="Visualize ARM Prerequisite Rules")
    parser.add_argument("path", help="Path to arm_rules.txt / arm_rules.csv or artifact directory")
    parser.add_argument("--name", default="CVE", help="Benchmark name for titles and tables")
    args = parser.parse_args()
    
    target_path = args.path
    if os.path.isdir(target_path):
        # Scan for arm_rules.txt or arm_rules.csv inside directory
        candidates = []
        for root, dirs, files in os.walk(target_path):
            for file in files:
                if file in ["arm_rules.txt", "arm_rules.csv"]:
                    candidates.append(os.path.join(root, file))
        if not candidates:
            print(f"Error: No arm_rules.txt or arm_rules.csv found under directory {target_path}")
            sys.exit(1)
        target_path = candidates[0]
        print(f"[+] Found rule file: {target_path}")
        
    df = load_arm_rules(target_path)
    if df is None or len(df) == 0:
        print("[-] No ARM rules found or file empty.")
        sys.exit(0)
        
    abs_path = os.path.abspath(target_path)
    out_dir = os.path.dirname(abs_path)
    png_name = "arm_heatmap.png"
    
    # Try to redirect to unified plot directory under artifact
    if "artifact" in abs_path:
        parts = abs_path.split("artifact" + os.sep)
        if len(parts) > 1:
            subparts = parts[1].split(os.sep)
            if len(subparts) >= 4:
                cve = subparts[0]
                session_dir = subparts[1]
                method = subparts[2]
                trial = subparts[3]
                root_dir = parts[0]
                unified_plot_dir = os.path.join(root_dir, "artifact", cve, "plot", session_dir, trial)
                os.makedirs(unified_plot_dir, exist_ok=True)
                out_dir = unified_plot_dir
                png_name = f"{method}_arm_heatmap.png"
            elif len(subparts) >= 2:
                cve = subparts[0]
                session_dir = subparts[1]
                root_dir = parts[0]
                unified_plot_dir = os.path.join(root_dir, "artifact", cve, "plot", session_dir)
                os.makedirs(unified_plot_dir, exist_ok=True)
                out_dir = unified_plot_dir
                
    print(f"\n[+] Processing {len(df)} ARM rules for {args.name}...")
    
    png_path = os.path.join(out_dir, png_name)
    plot_heatmap(df, png_path, title=f"ARM Rule Adjacency Heatmap - {args.name}")

if __name__ == "__main__":
    main()

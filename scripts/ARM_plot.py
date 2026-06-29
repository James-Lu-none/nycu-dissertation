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
        sns.heatmap(matrix, cmap="Viridis", cbar_kws={'label': 'Seed Support'}, robust=True)
        plt.title(title, fontsize=14, fontweight='bold')
        plt.xlabel("Target Block (Dst)", fontsize=12)
        plt.ylabel("Prerequisite Block (Src)", fontsize=12)
        plt.tight_layout()
        plt.savefig(output_path, dpi=300)
        plt.close()
        print(f"[+] Saved Heatmap to {output_path}")
    except ImportError:
        print("[-] matplotlib/seaborn not installed. Skipping heatmap generation.")

def generate_interactive_html(df, output_path, title="ARM Dependency Graph", max_nodes=200):
    """Generate standalone interactive HTML graph using vis.js CDN."""
    # Limit nodes for smooth rendering if needed
    if len(df) > max_nodes:
        print(f"[i] Graph has {len(df)} edges. Filtering top {max_nodes} edges by support for interactive visualization...")
        df_plot = df.sort_values(by='support', ascending=False).head(max_nodes)
    else:
        df_plot = df

    nodes = set(df_plot['src_block'].unique()).union(set(df_plot['dst_block'].unique()))
    
    nodes_json = []
    for n in sorted(nodes):
        nodes_json.append(f"{{id: {n}, label: 'Block {n}', shape: 'dot', size: 15, color: '#4a90e2'}}")
        
    edges_json = []
    for _, row in df_plot.iterrows():
        u = int(row['src_block'])
        v = int(row['dst_block'])
        w = int(row['support'])
        edges_json.append(f"{{from: {u}, to: {v}, arrows: 'to', title: 'Support: {w} seeds', value: {w}, color: '#e74c3c'}}")
        
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style type="text/css">
        #network {{
            width: 100%;
            height: 90vh;
            border: 1px solid lightgray;
            background-color: #222222;
        }}
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 10px;
            background-color: #1a1a1a;
            color: #ffffff;
        }}
        h2 {{ margin-top: 0; }}
    </style>
</head>
<body>
    <h2>{title} (Total Rules: {len(df)})</h2>
    <div id="network"></div>
    <script type="text/javascript">
        var nodes = new vis.DataSet([{','.join(nodes_json)}]);
        var edges = new vis.DataSet([{','.join(edges_json)}]);
        var container = document.getElementById('network');
        var data = {{ nodes: nodes, edges: edges }};
        var options = {{
            nodes: {{ font: {{ color: '#ffffff' }} }},
            edges: {{ smooth: {{ type: 'cubicBezier' }} }},
            physics: {{
                barnesHut: {{ gravitationalConstant: -3000, centralGravity: 0.3, springLength: 95 }}
            }}
        }};
        var network = new vis.Network(container, data, options);
    </script>
</body>
</html>
"""
    with open(output_path, 'w') as f:
        f.write(html_content)
    print(f"[+] Saved Interactive Graph to {output_path}")

def print_latex_table(df, benchmark_name="CVE"):
    """Print publication-ready LaTeX booktabs table summary."""
    total_rules = len(df)
    total_src = df['src_block'].nunique()
    total_dst = df['dst_block'].nunique()
    avg_support = df['support'].mean() if total_rules > 0 else 0
    max_support = df['support'].max() if total_rules > 0 else 0
    
    print("\n" + "="*50)
    print("      LaTeX Booktabs Table Summary (For Paper)")
    print("="*50)
    latex_code = f"""\\begin{{table}}[htbp]
\\centering
\\caption{{Summary of dynamic ARM prerequisite rules for {benchmark_name}.}}
\\label{{tab:arm_summary_{benchmark_name.lower().replace('-', '_')}}}
\\begin{{tabular}}{{lcccc}}
\\toprule
\\textbf{{Benchmark}} & \\textbf{{Total Rules ($|R|$)}} & \\textbf{{Prereq Blocks}} & \\textbf{{Max Support}} & \\textbf{{Avg Support}} \\\\
\\midrule
{benchmark_name} & {total_rules:,} & {total_src} & {max_support} seeds & {avg_support:.1f} seeds \\\\
\\bottomrule
\\end{{tabular}}
\\end{{table}}"""
    print(latex_code)
    print("="*50 + "\n")

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
        
    out_dir = os.path.dirname(os.path.abspath(target_path))
    
    print(f"\n[+] Processing {len(df)} ARM rules for {args.name}...")
    
    # 1. Generate Interactive HTML Network
    html_path = os.path.join(out_dir, "arm_network.html")
    generate_interactive_html(df, html_path, title=f"ARM Dependency Network - {args.name}")
    
    # 2. Generate Heatmap PNG
    png_path = os.path.join(out_dir, "arm_heatmap.png")
    plot_heatmap(df, png_path, title=f"ARM Rule Adjacency Heatmap - {args.name}")
    
    # 3. Print LaTeX Summary Table
    print_latex_table(df, benchmark_name=args.name)

if __name__ == "__main__":
    main()

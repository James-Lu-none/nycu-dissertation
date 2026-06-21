#!/usr/bin/env python3
import os
import re
import sys
import argparse

def get_method_label(method):
    m_low = method.lower()
    if "dual-cd" in m_low:
        return "Dual CD+DD (CD Fuzzer)"
    elif "dual-dd" in m_low:
        return "Dual CD+DD (DD Fuzzer)"
    elif "cd" in m_low:
        return "Control Dependency (cd)"
    elif "dd" in m_low:
        return "Data Dependency (dd)"
    elif "base" in m_low:
        return "Baseline (base)"
    else:
        return method

def generate_tte_summary_plot(method_ttes, output_path, cve):
    """
    Generates Time to Bug Exposure (TTE) box plot.
    """
    try:
        import matplotlib.pyplot as plt
        import numpy as np
        import textwrap
    except ImportError:
        print("Warning: matplotlib, numpy or textwrap not installed. Skipping plot generation.")
        return

    # Filter out empty datasets
    data_to_plot = []
    labels = []
    text_lines = []

    # Sort methods: base (0), dd (1), cd (2), dual-dd (3), dual-cd (4)
    def get_sort_key(m):
        m_low = m.lower()
        if "dual-cd" in m_low:
            return 4
        elif "dual-dd" in m_low:
            return 3
        elif "cd" in m_low:
            return 2
        elif "dd" in m_low:
            return 1
        elif "base" in m_low:
            return 0
        return 5
        
    sorted_methods = sorted(method_ttes.keys(), key=get_sort_key)

    for method in sorted_methods:
        ttes = method_ttes[method]
        total_trials = len(ttes)
        if total_trials == 0:
            continue

        # Filter and sort valid TTEs
        valid_ttes = [t for t in ttes if t is not None]
        valid_ttes.sort()

        if len(valid_ttes) > 0:
            data_to_plot.append(valid_ttes)
        else:
            data_to_plot.append([np.nan])

        raw_label = get_method_label(method)
        wrapped_label = textwrap.fill(raw_label, width=20)
        labels.append(wrapped_label)

        # Calculate metrics
        if valid_ttes:
            geo_mean = np.exp(np.mean(np.log(valid_ttes)))
            mean_val = np.mean(valid_ttes)
            success_rate = len(valid_ttes) / total_trials * 100.0
            text_lines.append(f"{method} ({len(valid_ttes)}/{total_trials} - {success_rate:.0f}%):")
            text_lines.append(f"  Geo Mean: {geo_mean:.2f}s")
            text_lines.append(f"  Mean: {mean_val:.2f}s")
        else:
            text_lines.append(f"{method} (0/{total_trials}):")
            text_lines.append(f"  No exposure")

    if not data_to_plot:
        print("Warning: No data to plot.")
        return

    plt.figure(figsize=(10, 6))

    colors_map = {
        'dual-cd': '#d62728', # red
        'dual-dd': '#ff7f0e', # orange
        'cd': '#2ca02c',       # green
        'dd': '#1f77b4',       # blue
        'base': '#7f7f7f'      # gray
    }

    # Calculate speedup relative to the baseline (base, otherwise dd)
    base_method = next((m for m in method_ttes.keys() if 'base' in m.lower()), None)
    if not base_method:
        base_method = next((m for m in method_ttes.keys() if 'dd' in m.lower() and 'cd' not in m.lower()), None)
        
    if base_method:
        base_valid = [t for t in method_ttes[base_method] if t is not None]
        if base_valid:
            geo_mean_base = np.exp(np.mean(np.log(base_valid)))
            for method in sorted_methods:
                if method == base_method:
                    continue
                valid_ttes = [t for t in method_ttes[method] if t is not None]
                if valid_ttes:
                    geo_mean_m = np.exp(np.mean(np.log(valid_ttes)))
                    if geo_mean_m > 0:
                        speedup = geo_mean_base / geo_mean_m
                        text_lines.append(f"Geo Mean Speedup ({method} vs {base_method}): {speedup:.2f}x")

    # Create box plot
    bp = plt.boxplot(data_to_plot, patch_artist=True, tick_labels=labels, widths=0.4,
                     showmeans=True, meanline=True,
                     medianprops=dict(color='black', linewidth=1.5),
                     meanprops=dict(color='red', linewidth=1.5, linestyle='--'))

    # Color boxes and set custom styles
    for i, (patch, method) in enumerate(zip(bp['boxes'], sorted_methods)):
        color = '#1f77b4'  # default blue
        for key, val in colors_map.items():
            if key in method.lower():
                color = val
                break
        
        # Style the box
        patch.set_facecolor(color)
        patch.set_alpha(0.6)
        patch.set_edgecolor(color)
        patch.set_linewidth(1.5)

        # Style whiskers, caps, and fliers matching the box color
        bp['whiskers'][2*i].set_color(color)
        bp['whiskers'][2*i].set_linewidth(1.5)
        bp['whiskers'][2*i+1].set_color(color)
        bp['whiskers'][2*i+1].set_linewidth(1.5)
        
        bp['caps'][2*i].set_color(color)
        bp['caps'][2*i].set_linewidth(1.5)
        bp['caps'][2*i+1].set_color(color)
        bp['caps'][2*i+1].set_linewidth(1.5)
        
        bp['fliers'][i].set_markeredgecolor(color)
        bp['fliers'][i].set_marker('o')
        bp['fliers'][i].set_markersize(6)

        # Overlay individual trial points (jittered)
        ttes = method_ttes[method]
        valid_ttes = [t for t in ttes if t is not None]
        if valid_ttes:
            x_jitter = np.random.normal(i + 1, 0.04, size=len(valid_ttes))
            plt.scatter(x_jitter, valid_ttes, color=color, edgecolor='black', alpha=0.8, s=45, zorder=3)

    plt.title(f'Time to Bug Exposure (TTE) Distribution ({cve})', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Fuzzing Configuration', fontsize=12)
    plt.ylabel('Elapsed Time to Exposure (seconds)', fontsize=12)
    plt.grid(True, axis='y', linestyle=':', alpha=0.6)

    # Add legend manually
    import matplotlib.patches as mpatches
    legend_patches = []
    for method in sorted_methods:
        color = '#1f77b4'
        for key, val in colors_map.items():
            if key in method.lower():
                color = val
                break
        raw_label = get_method_label(method)
        legend_patches.append(mpatches.Patch(color=color, alpha=0.6, label=f"{raw_label} ({method})"))
    
    import matplotlib.lines as mlines
    mean_line = mlines.Line2D([], [], color='red', linestyle='--', linewidth=1.5, label='Mean')
    median_line = mlines.Line2D([], [], color='black', linestyle='-', linewidth=1.5, label='Median')
    legend_patches.extend([mean_line, median_line])
    
    plt.legend(handles=legend_patches, loc='best', fontsize=10)

    if text_lines:
        textstr = "\n".join(text_lines)
        props = dict(boxstyle='round', facecolor='#e6f2ff', alpha=0.8, edgecolor='#1f77b4')
        plt.text(1.02, 1.0, textstr, transform=plt.gca().transAxes, fontsize=10,
                 verticalalignment='top', bbox=props, fontweight='bold')

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Summary box plot successfully saved as '{output_path}'")

def parse_exposure_file(file_path):
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            if "Target not reached" in content:
                return None
            match = re.search(r'Elapsed:\s+([\d\.]+)\s+seconds', content)
            if match:
                return float(match.group(1))
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
    return None

def main():
    parser = argparse.ArgumentParser(description="Generate TTE comparison summary plot from exposure files.")
    parser.add_argument("--bench", required=True, help="Full benchmark directory name (e.g. libming-4.8.1_swftophp_CVE-2019-9114)")
    parser.add_argument("--root", default="./artifact", help="Root directory of the CVE artifact data")
    args = parser.parse_args()

    # Locate artifact directory
    artifact_dir = os.path.join(args.root, args.bench)
    if not os.path.exists(artifact_dir):
        print(f"Error: Artifact directory {artifact_dir} not found. Exiting.")
        sys.exit(1)
        
    methods = [d for d in os.listdir(artifact_dir) if os.path.isdir(os.path.join(artifact_dir, d)) and d != "plot"]
    if not methods:
        print(f"Error: No fuzzer method directories found under {artifact_dir}. Exiting.")
        sys.exit(1)
    print(f"Detected fuzzer methods: {methods}")

    # Read TTEs from existing dgf_target_exposure.txt files
    print("Reading TTEs from existing dgf_target_exposure.txt files...")
    method_ttes = {}
    for method in methods:
        method_dir = os.path.join(artifact_dir, method)
        trials = [t for t in os.listdir(method_dir) if os.path.isdir(os.path.join(method_dir, t)) and t.startswith("trial")]
        
        def sort_key(x):
            digits = re.search(r'\d+', x)
            return (0, int(digits.group())) if digits else (1, x)
        trials.sort(key=sort_key)
        
        method_ttes[method] = []
        for trial in trials:
            exposure_file_path = os.path.join(method_dir, trial, "dgf_target_exposure.txt")
            tte = parse_exposure_file(exposure_file_path)
            method_ttes[method].append(tte)

    # Generate overall summary TTE plot
    if method_ttes:
        print("\n================ Generating TTE Summary Plot ================")
        plot_dir = os.path.join(artifact_dir, "plot")
        os.makedirs(plot_dir, exist_ok=True)
        tte_summary_path = os.path.join(plot_dir, "TTE_comparison_summary.png")
        generate_tte_summary_plot(method_ttes, tte_summary_path, args.bench)

if __name__ == '__main__':
    main()

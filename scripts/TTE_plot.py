#!/usr/bin/env python3
import os
import re
import sys
import argparse

def get_method_label(method):
    m_low = method.lower()
    if "dual" in m_low:
        return "dual"
    elif "cd" in m_low:
        return "cd"
    elif "dd" in m_low:
        return "dd"
    elif "base" in m_low:
        return "base"
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

    data_to_plot = []
    labels = []
    text_lines = []

    def get_sort_key(m):
        m_low = m.lower()
        if "dual" in m_low:
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

        valid_ttes = [t for t in ttes if t is not None]
        valid_ttes.sort()

        if len(valid_ttes) > 0:
            data_to_plot.append(valid_ttes)
        else:
            data_to_plot.append([np.nan])

        raw_label = get_method_label(method)
        wrapped_label = textwrap.fill(raw_label, width=20)
        labels.append(wrapped_label)

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

    plt.figure(figsize=(5.5, 4.5))

    colors_map = {
        'dual': '#ff7f0e',    # orange
        'cd': '#2ca02c',       # green
        'dd': '#1f77b4',       # blue
        'base': '#7f7f7f'      # gray
    }

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

    bp = plt.boxplot(data_to_plot, patch_artist=True, tick_labels=labels, widths=0.5,
                     showmeans=False,
                     medianprops=dict(color='black', linewidth=1.5))

    for i, (patch, method) in enumerate(zip(bp['boxes'], sorted_methods)):
        color = '#1f77b4'
        for key, val in colors_map.items():
            if key in method.lower():
                color = val
                break
        
        patch.set_facecolor(color)
        patch.set_alpha(0.6)
        patch.set_edgecolor(color)
        patch.set_linewidth(1.5)

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

        ttes = method_ttes[method]
        valid_ttes = [t for t in ttes if t is not None]
        if valid_ttes:
            x_jitter = np.random.normal(i + 1, 0.04, size=len(valid_ttes))
            plt.scatter(x_jitter, valid_ttes, color=color, edgecolor='black', alpha=0.8, s=45, zorder=3)
            
            geo_mean = np.exp(np.mean(np.log(valid_ttes)))
            plt.hlines(y=geo_mean, xmin=i + 1 - 0.25, xmax=i + 1 + 0.25, colors='red', linestyles='--', linewidth=1.8, zorder=4)

    plt.title(f'TTE: {cve}', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Fuzzing Configuration', fontsize=12)
    plt.ylabel('Elapsed Time to Exposure (seconds)', fontsize=12)
    plt.grid(True, axis='y', linestyle=':', alpha=0.6)

    import matplotlib.patches as mpatches
    legend_patches = []
    for method in sorted_methods:
        color = '#1f77b4'
        for key, val in colors_map.items():
            if key in method.lower():
                color = val
                break
        raw_label = get_method_label(method)
        legend_patches.append(mpatches.Patch(color=color, alpha=0.6, label=raw_label))
    
    import matplotlib.lines as mlines
    geo_mean_line = mlines.Line2D([], [], color='red', linestyle='--', linewidth=1.5, label='Geo Mean')
    median_line = mlines.Line2D([], [], color='black', linestyle='-', linewidth=1.5, label='Median')
    legend_patches.extend([geo_mean_line, median_line])
    
    plt.legend(handles=legend_patches, loc='best', fontsize=10)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()

def generate_tte_table_image(method_ttes, output_path, cve):
    try:
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("Warning: matplotlib or numpy not installed. Skipping table generation.")
        return

    try:
        from scipy.stats import mannwhitneyu
    except ImportError:
        mannwhitneyu = None

    columns = ["Configuration", "Success Rate", "Geo Mean TTE", "Mean TTE", "Speedup", "p-value"]
    
    def get_sort_key(m):
        m_low = m.lower()
        if "dual" in m_low:
            return 3
        elif "cd" in m_low:
            return 2
        elif "dd" in m_low:
            return 1
        elif "base" in m_low:
            return 0
        return 5
    sorted_methods = sorted(method_ttes.keys(), key=get_sort_key)
    
    base_method = next((m for m in method_ttes.keys() if 'base' in m.lower()), None)
    base_geo_mean = None
    base_valid = []
    if base_method:
        base_valid = [t for t in method_ttes[base_method] if t is not None]
        if base_valid:
            base_geo_mean = np.exp(np.mean(np.log(base_valid)))
            
    cell_text = []
    for method in sorted_methods:
        ttes = method_ttes[method]
        total_trials = len(ttes)
        valid_ttes = [t for t in ttes if t is not None]
        
        success_str = f"{len(valid_ttes)}/{total_trials} ({len(valid_ttes)/total_trials*100.0:.0f}%)"
        
        if valid_ttes:
            geo_mean_val = np.exp(np.mean(np.log(valid_ttes)))
            mean_val = np.mean(valid_ttes)
            geo_mean_str = f"{geo_mean_val:.2f} s"
            mean_str = f"{mean_val:.2f} s"
            
            if base_geo_mean and geo_mean_val > 0:
                speedup_val = base_geo_mean / geo_mean_val
                speedup_str = f"{speedup_val:.2f}x"
            else:
                speedup_str = "1.00x" if method == base_method else "N.A."
        else:
            geo_mean_str = "N.A."
            mean_str = "N.A."
            speedup_str = "N.A."
            
        p_val_str = "-"
        if method != base_method:
            if valid_ttes and base_valid:
                if mannwhitneyu is not None:
                    try:
                        _, p_val = mannwhitneyu(valid_ttes, base_valid, alternative='two-sided')
                        if p_val < 0.0001:
                            p_val_str = f"{p_val:.2e}"
                        else:
                            p_val_str = f"{p_val:.4f}"
                    except Exception as e:
                        p_val_str = "error"
                else:
                    p_val_str = "no scipy"
            else:
                p_val_str = "N.A."

        label = get_method_label(method)
        cell_text.append([label, success_str, geo_mean_str, mean_str, speedup_str, p_val_str])
        
    fig, ax = plt.subplots(figsize=(7.5, len(sorted_methods) * 0.4 + 0.5))
    ax.axis('off')
    
    table = ax.table(
        cellText=cell_text,
        colLabels=columns,
        loc='center',
        cellLoc='center'
    )
    
    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1.2, 1.8)
    
    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_text_props(weight='bold', color='white')
            cell.set_facecolor('#1f77b4')
            cell.set_edgecolor('#1f77b4')
        else:
            if row % 2 == 0:
                cell.set_facecolor('#f2f2f2')
            else:
                cell.set_facecolor('white')
            cell.set_edgecolor('#e0e0e0')
            
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Summary table successfully saved as '{output_path}'")

    import csv
    csv_path = output_path.replace(".png", ".csv")
    try:
        with open(csv_path, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(columns)
            writer.writerows(cell_text)
        print(f"CSV data successfully saved as '{csv_path}'")
    except Exception as e:
        print(f"Error saving CSV to {csv_path}: {e}")

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
    parser.add_argument("--trial-name", type=str, help="Specific trial run name to plot. If not specified, the latest one will be used.")
    args = parser.parse_args()

    artifact_dir = os.path.join(args.root, args.bench)
    if not os.path.exists(artifact_dir):
        print(f"Error: Artifact directory {artifact_dir} not found. Exiting.")
        sys.exit(1)
        
    trial_names = set()
    for d in os.listdir(artifact_dir):
        if os.path.isdir(os.path.join(artifact_dir, d)) and d not in ["plot", "TTE_check"]:
            base = re.sub(r'_\d{8}_\d{6}$', '', d)
            trial_names.add(base)
    
    if not trial_names:
        print(f"Error: No trial runs found under {artifact_dir}. Exiting.")
        sys.exit(1)
        
    trial_name = args.trial_name
    if trial_name and trial_name.lower() != 'all':
        trial_name_base = re.sub(r'_\d{8}_\d{6}$', '', trial_name)
    else:
        trial_name_base = None

    if not trial_name_base:
        session_dirs = []
        for d in os.listdir(artifact_dir):
            if os.path.isdir(os.path.join(artifact_dir, d)) and d not in ["plot", "TTE_check"]:
                session_dirs.append(d)
        if not session_dirs:
            print(f"Error: No trial runs found under {artifact_dir}. Exiting.")
            sys.exit(1)
        trial_name = "all"
        trial_name_base = "all"
    else:
        if trial_name_base not in trial_names:
            print(f"Error: Specified trial-name '{trial_name}' not found under {artifact_dir}. Available base names: {list(trial_names)}")
            sys.exit(1)
            
        # Find matching session directories
        session_dirs = []
        for d in os.listdir(artifact_dir):
            if os.path.isdir(os.path.join(artifact_dir, d)) and d not in ["plot", "TTE_check"]:
                if d == trial_name:
                    session_dirs.append(d)
                elif not re.search(r'_\d{8}_\d{6}$', trial_name) and re.match(r"^" + re.escape(trial_name_base) + r"(_\d{8}_\d{6})?$", d):
                    session_dirs.append(d)
                
    def sort_session_key(x):
        ts_match = re.search(r'_(\d{8}_\d{6})$', x)
        return ts_match.group(1) if ts_match else ""
    session_dirs.sort(key=sort_session_key)

    # Find fuzzer methods from the first session path
    first_session_path = os.path.join(artifact_dir, session_dirs[0])
    methods = [d for d in os.listdir(first_session_path) if os.path.isdir(os.path.join(first_session_path, d)) and d not in ["plot", "TTE_check", ".session_id"]]
    if not methods:
        print(f"Error: No fuzzer method directories found under {first_session_path}. Exiting.")
        sys.exit(1)
        
    # Gather all trial items under matching sessions
    trial_items = []
    def sort_trial_key(x):
        digits = re.search(r'\d+', x)
        return int(digits.group()) if digits else 999

    for session_dir in session_dirs:
        session_path = os.path.join(artifact_dir, session_dir)
        existing_trials = set()
        for m in os.listdir(session_path):
            m_path = os.path.join(session_path, m)
            if os.path.isdir(m_path) and m not in ["plot", "TTE_check"]:
                for t in os.listdir(m_path):
                    if os.path.isdir(os.path.join(m_path, t)) and t.startswith("trial"):
                        existing_trials.add(t)
        sorted_existing = sorted(list(existing_trials), key=sort_trial_key)
        for t in sorted_existing:
            trial_items.append({
                "session_dir": session_dir,
                "trial": t,
                "label": f"{session_dir}_{t}" if len(session_dirs) > 1 else t
            })
            
    print(f"Detected fuzzer methods: {methods}")
    print(f"Detected matching trial items ({len(trial_items)}): {[t['label'] for t in trial_items]}")
    print("Reading TTEs from existing dgf_target_exposure.txt files...")
    method_ttes = {}
    for method in methods:
        method_ttes[method] = []
        for item in trial_items:
            exposure_file_path = os.path.join(artifact_dir, item["session_dir"], method, item["trial"], "dgf_target_exposure.txt")
            tte = parse_exposure_file(exposure_file_path)
            method_ttes[method].append(tte)

    # Combine dual-dd and dual-cd into a single method "dual"
    dual_keys = [k for k in method_ttes.keys() if "dual" in k.lower()]
    if dual_keys:
        max_trials = max(len(method_ttes[k]) for k in dual_keys)
        dual_ttes = []
        for i in range(max_trials):
            trial_vals = []
            for k in dual_keys:
                if i < len(method_ttes[k]) and method_ttes[k][i] is not None:
                    trial_vals.append(method_ttes[k][i])
            if trial_vals:
                dual_ttes.append(min(trial_vals))
            else:
                dual_ttes.append(None)
        for k in dual_keys:
            del method_ttes[k]
        method_ttes["dual"] = dual_ttes

    if method_ttes:
        print("\n================ Generating TTE Summary Plot & Table ================")
        plot_dir = os.path.join(artifact_dir, "plot")
        os.makedirs(plot_dir, exist_ok=True)
        
        if trial_name == "all":
            tte_summary_path = os.path.join(plot_dir, "TTE_comparison_summary.png")
            tte_table_path = os.path.join(plot_dir, "TTE_summary_table.png")
        else:
            tte_summary_path = os.path.join(plot_dir, f"{trial_name}_TTE_comparison_summary.png")
            tte_table_path = os.path.join(plot_dir, f"{trial_name}_TTE_summary_table.png")
            
        generate_tte_summary_plot(method_ttes, tte_summary_path, args.bench)
        generate_tte_table_image(method_ttes, tte_table_path, args.bench)

if __name__ == '__main__':
    main()

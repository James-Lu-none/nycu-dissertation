#!/usr/bin/env python3
import os
import re
import argparse
import numpy as np
import matplotlib.pyplot as plt

def parse_plot_data(file_path):
    def parse_single(path):
        times = []
        edges = []
        execs = []
        if not os.path.exists(path):
            return times, edges, execs
        
        try:
            with open(path, 'r') as f:
                lines = f.readlines()
                
            header = None
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('#'):
                    header_parts = [h.strip() for h in line.lstrip('#').split(',')]
                    header = header_parts
                    continue
                
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 13:
                    try:
                        if header:
                            time_idx = header.index('relative_time') if 'relative_time' in header else 0
                            edges_idx = header.index('edges_found') if 'edges_found' in header else 12
                            execs_idx = header.index('total_execs') if 'total_execs' in header else 11
                        else:
                            time_idx = 0
                            edges_idx = 12
                            execs_idx = 11
                            
                        times.append(float(parts[time_idx]))
                        edges.append(int(parts[edges_idx]))
                        execs.append(int(parts[execs_idx]))
                    except (ValueError, IndexError):
                        continue
        except Exception as e:
            print(f"Error parsing {path}: {e}")
            
        return times, edges, execs

    series1 = parse_single(file_path)
    
    # Check if there is a slave plot_data in the sibling 'slave' folder
    if "/out/main/" in file_path:
        slave_path = file_path.replace("/out/main/", "/out/slave/")
        if os.path.exists(slave_path):
            series2 = parse_single(slave_path)
            
            times1, edges1, execs1 = series1
            times2, edges2, execs2 = series2
            
            if not times1:
                return times2, edges2, execs2
            if not times2:
                return times1, edges1, execs1
                
            all_times = sorted(list(set(times1 + times2)))
            merged_edges = []
            merged_execs = []
            
            for t in all_times:
                e1 = np.interp(t, times1, edges1)
                x1 = np.interp(t, times1, execs1)
                
                e2 = np.interp(t, times2, edges2)
                x2 = np.interp(t, times2, execs2)
                
                merged_edges.append(int(max(e1, e2)))
                merged_execs.append(int(x1 + x2))
                
            return all_times, merged_edges, merged_execs
            
    return series1

def interpolate_run(times, values, common_grid):
    if not times or not values:
        return np.zeros_like(common_grid)
    
    t_arr = np.array(times)
    v_arr = np.array(values)
    
    if t_arr[-1] < common_grid[-1]:
        t_arr = np.append(t_arr, common_grid[-1])
        v_arr = np.append(v_arr, v_arr[-1])
        
    if t_arr[0] > common_grid[0]:
        t_arr = np.insert(t_arr, 0, common_grid[0])
        v_arr = np.insert(v_arr, 0, v_arr[1])
        
    return np.interp(common_grid, t_arr, v_arr)

def geometric_mean(arrays, axis=0):
    with np.errstate(divide='ignore', invalid='ignore'):
        log_data = np.log(arrays)
        mean_log = np.mean(log_data, axis=axis)
        geomean = np.exp(mean_log)
    return np.nan_to_num(geomean, nan=0.0)

def parse_corpus_imported(file_path):
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if 'corpus_imported' in line:
                    match = re.search(r'corpus_imported\s*:\s*(\d+)', line)
                    if match:
                        return int(match.group(1))
    except Exception as e:
        print(f"Error parsing corpus_imported in {file_path}: {e}")
    return None

def get_fuzzer_name(method):
    m_low = method.lower()
    if "dual-cd" in m_low:
        return "cd"
    elif "dual-dd" in m_low:
        return "dd"
    return "main"

def get_method_info(method):
    m_low = method.lower()
    if "dual-cd" in m_low:
        return "Dual CD+DD (CD Fuzzer)", "#d62728"
    elif "dual-dd" in m_low:
        return "Dual CD+DD (DD Fuzzer)", "#ff7f0e"
    elif "cd" in m_low:
        return "Control Dependency (cd)", "#2ca02c"
    elif "dd" in m_low:
        return "Data Dependency (dd)", "#1f77b4"
    elif "base" in m_low:
        return "Baseline (base)", "#7f7f7f"
    return method, "#7f7f7f"

def plot_single_trial(methods, method_data, output_dir, cve="CVE"):
    os.makedirs(output_dir, exist_ok=True)
    
    text_lines = []
    base_method = methods[0]
    base_edge = method_data[base_method][1][-1] if method_data[base_method][1] else 0
    
    for method in methods:
        times, edges, execs = method_data[method]
        final_edge = edges[-1] if edges else 0
        label, _ = get_method_info(method)
        text_lines.append(f"{method}: {final_edge} edges")
        if method != base_method and base_edge > 0:
            impr = (final_edge - base_edge) / base_edge * 100
            text_lines.append(f"  vs {base_method}: {impr:+.1f}%")
            
    textstr = "\n".join(text_lines) if text_lines else ""
    props = dict(boxstyle='round', facecolor='#e6f2ff', alpha=0.8, edgecolor='#1f77b4')
    
    plt.figure(figsize=(10, 6))
    for method in methods:
        times, edges, _ = method_data[method]
        if times:
            label, color = get_method_info(method)
            plt.plot(np.array(times), edges, label=label, color=color, linewidth=2)
            
    if textstr:
        plt.text(1.02, 1.0, textstr, transform=plt.gca().transAxes, fontsize=10,
                 verticalalignment='top', bbox=props)
                 
    plt.title(f'Edge Coverage Over Time ({cve})', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Elapsed Time (seconds)', fontsize=12)
    plt.ylabel('Unique Edges Found', fontsize=12)
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(loc='lower right', fontsize=10)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'coverage_time.png'), dpi=300, bbox_inches='tight')
    plt.close()
    
    plt.figure(figsize=(10, 6))
    for method in methods:
        _, edges, execs = method_data[method]
        if execs:
            label, color = get_method_info(method)
            plt.plot(np.array(execs) / 1e6, edges, label=label, color=color, linewidth=2)
            
    if textstr:
        plt.text(1.02, 1.0, textstr, transform=plt.gca().transAxes, fontsize=10,
                 verticalalignment='top', bbox=props)
                 
    plt.title(f'Edge Coverage vs Total Executions ({cve})', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Total Executions (millions)', fontsize=12)
    plt.ylabel('Unique Edges Found', fontsize=12)
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(loc='lower right', fontsize=10)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'coverage_execs.png'), dpi=300, bbox_inches='tight')
    plt.close()

def main():
    parser = argparse.ArgumentParser(description="Generate coverage plots.")
    parser.add_argument("--root", type=str, required=True, help="Root directory of the CVE artifact data")
    parser.add_argument("--methods", type=str, nargs="+", required=True, help="Fuzzer methods to compare")
    parser.add_argument("--cve", type=str, default="CVE", help="CVE identifier")
    parser.add_argument("--trial-name", type=str, help="Specific trial run name to plot. If not specified, the latest one will be used.")
    args = parser.parse_args()
    
    root = os.path.expanduser(args.root)
    methods = args.methods
    plot_base_dir = os.path.join(root, "plot")
    
    trial_names = set()
    for d in os.listdir(root):
        if os.path.isdir(os.path.join(root, d)) and d not in ["plot", "TTE_check"]:
            base = re.sub(r'_\d{8}_\d{6}$', '', d)
            trial_names.add(base)
                
    if not trial_names:
        print("Error: No trial runs found.")
        return
        
    trial_name = args.trial_name
    if trial_name and trial_name.lower() != 'all':
        trial_name_base = re.sub(r'_\d{8}_\d{6}$', '', trial_name)
    else:
        trial_name_base = None

    if not trial_name_base:
        session_dirs = []
        for d in os.listdir(root):
            if os.path.isdir(os.path.join(root, d)) and d not in ["plot", "TTE_check"]:
                session_dirs.append(d)
        if not session_dirs:
            print("Error: No trial runs found.")
            return
        trial_name = "all"
        trial_name_base = "all"
    else:
        if trial_name_base not in trial_names:
            print(f"Error: Specified trial-name '{trial_name}' not found. Available base names: {list(trial_names)}")
            sys.exit(1)
            
        # Find matching session directories
        session_dirs = []
        for d in os.listdir(root):
            if os.path.isdir(os.path.join(root, d)) and d not in ["plot", "TTE_check"]:
                if d == trial_name:
                    session_dirs.append(d)
                elif not re.search(r'_\d{8}_\d{6}$', trial_name) and re.match(r"^" + re.escape(trial_name_base) + r"(_\d{8}_\d{6})?$", d):
                    session_dirs.append(d)
                
    def sort_session_key(x):
        ts_match = re.search(r'_(\d{8}_\d{6})$', x)
        return ts_match.group(1) if ts_match else ""
    session_dirs.sort(key=sort_session_key)

    # Find fuzzer methods from the first session path
    first_session_path = os.path.join(root, session_dirs[0])
    valid_methods = []
    for m in methods:
        if os.path.exists(os.path.join(first_session_path, m)):
            if m.lower() == "dual":
                valid_methods.append("dual-dd")
                valid_methods.append("dual-cd")
            else:
                valid_methods.append(m)
                
    if not valid_methods:
        print("No valid method directories found.")
        return
        
    # Gather all trial items under matching sessions
    trial_items = []
    def sort_trial_key(x):
        digits = re.search(r'\d+', x)
        return int(digits.group()) if digits else 999

    for session_dir in session_dirs:
        session_path = os.path.join(root, session_dir)
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
            
    print(f"Valid methods: {valid_methods}")
    print(f"Detected matching trial items ({len(trial_items)}): {[t['label'] for t in trial_items]}")
    
    method_runs_time = {m: [] for m in valid_methods}
    method_runs_exec = {m: [] for m in valid_methods}
    
    max_time_all = 0
    max_exec_all = 0
    
    for item in trial_items:
        print(f"\n================ Processing Coverage for {item['label']} ================")
        trial_method_data = {}
        
        for method in valid_methods:
            fuzzer_name = get_fuzzer_name(method)
            dir_method = "dual" if method.startswith("dual-") else method
            plot_file = os.path.join(root, item["session_dir"], dir_method, item["trial"], f"out/{fuzzer_name}/plot_data")
            times, edges, execs = parse_plot_data(plot_file)
            trial_method_data[method] = (times, edges, execs)
            
            if times:
                method_runs_time[method].append((times, edges))
                method_runs_exec[method].append((execs, edges))
                max_time_all = max(max_time_all, times[-1])
                max_exec_all = max(max_exec_all, execs[-1])
                
        output_dir = os.path.join(plot_base_dir, item["session_dir"], item["trial"])
        print(f"Plotting single-trial coverage to {output_dir}...")
        plot_single_trial(valid_methods, trial_method_data, output_dir, cve=args.cve)
        
    print("\n================ Generating Coverage Summary Plots ================")
    os.makedirs(plot_base_dir, exist_ok=True)
    
    common_times = np.linspace(0, max_time_all, num=1000)
    plt.figure(figsize=(10, 6))
    
    method_means_time = {}
    
    for idx, method in enumerate(valid_methods):
        label, color = get_method_info(method)
        runs = method_runs_time[method]
        interp_runs = [interpolate_run(r[0], r[1], common_times) for r in runs if r[0]]
        
        if not interp_runs:
            continue
            
        for i, interp in enumerate(interp_runs):
            lbl = f'{label} (individual)' if i == 0 else ""
            plt.plot(common_times, interp, color=color, alpha=0.2, linewidth=1, label=lbl)
            
        mean_curve = geometric_mean(interp_runs, axis=0)
        std_curve = np.std(interp_runs, axis=0)
        method_means_time[method] = mean_curve[-1]
        
        plt.plot(common_times, mean_curve, color=color, linewidth=2.5, label=f'{label} (average)')
        plt.fill_between(common_times, np.maximum(0, mean_curve - std_curve), mean_curve + std_curve, color=color, alpha=0.1)
        
    text_lines = []
    base_method = valid_methods[0]
    base_avg_time = method_means_time.get(base_method, 0.0)
    
    for method in valid_methods:
        avg_val = method_means_time.get(method, 0.0)
        text_lines.append(f"Avg {method}: {avg_val:.1f} edges")
        if method != base_method and base_avg_time > 0:
            impr = (avg_val - base_avg_time) / base_avg_time * 100
            text_lines.append(f"  vs {base_method}: {impr:+.1f}%")
            
    if text_lines:
        textstr = "\n".join(text_lines)
        props = dict(boxstyle='round', facecolor='#e6f2ff', alpha=0.8, edgecolor='#1f77b4')
        plt.text(1.02, 1.0, textstr, transform=plt.gca().transAxes, fontsize=10,
                 verticalalignment='top', bbox=props, fontweight='bold')
                 
    plt.title(f'Edge Coverage Over Time ({args.cve})', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Elapsed Time (seconds)', fontsize=12)
    plt.ylabel('Unique Edges Found', fontsize=12)
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(loc='lower right', fontsize=10)
    plt.tight_layout()
    if trial_name == "all":
        time_summary_path = os.path.join(plot_base_dir, 'coverage_time_summary.png')
    else:
        time_summary_path = os.path.join(plot_base_dir, f'{trial_name}_coverage_time_summary.png')
    plt.savefig(time_summary_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Summary plot saved as '{time_summary_path}'")
    
    common_execs = np.linspace(0, max_exec_all, num=1000)
    plt.figure(figsize=(10, 6))
    
    method_means_exec = {}
    
    for idx, method in enumerate(valid_methods):
        label, color = get_method_info(method)
        runs = method_runs_exec[method]
        interp_runs = [interpolate_run(r[0], r[1], common_execs) for r in runs if r[0]]
        
        if not interp_runs:
            continue
            
        for i, interp in enumerate(interp_runs):
            lbl = f'{label} (individual)' if i == 0 else ""
            plt.plot(common_execs / 1e6, interp, color=color, alpha=0.2, linewidth=1, label=lbl)
            
        mean_curve = geometric_mean(interp_runs, axis=0)
        std_curve = np.std(interp_runs, axis=0)
        method_means_exec[method] = mean_curve[-1]
        
        plt.plot(common_execs / 1e6, mean_curve, color=color, linewidth=2.5, label=f'{label} (average)')
        plt.fill_between(common_execs / 1e6, np.maximum(0, mean_curve - std_curve), mean_curve + std_curve, color=color, alpha=0.1)
        
    text_lines = []
    base_avg_exec = method_means_exec.get(base_method, 0.0)
    
    for method in valid_methods:
        avg_val = method_means_exec.get(method, 0.0)
        text_lines.append(f"Avg {method}: {avg_val:.1f} edges")
        if method != base_method and base_avg_exec > 0:
            impr = (avg_val - base_avg_exec) / base_avg_exec * 100
            text_lines.append(f"  vs {base_method}: {impr:+.1f}%")
            
    if text_lines:
        textstr = "\n".join(text_lines)
        props = dict(boxstyle='round', facecolor='#e6f2ff', alpha=0.8, edgecolor='#1f77b4')
        plt.text(1.02, 1.0, textstr, transform=plt.gca().transAxes, fontsize=10,
                 verticalalignment='top', bbox=props, fontweight='bold')
                 
    plt.title(f'Edge Coverage vs Total Executions ({args.cve})', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Total Executions (millions)', fontsize=12)
    plt.ylabel('Unique Edges Found', fontsize=12)
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(loc='lower right', fontsize=10)
    plt.tight_layout()
    if trial_name == "all":
        execs_summary_path = os.path.join(plot_base_dir, 'coverage_execs_summary.png')
    else:
        execs_summary_path = os.path.join(plot_base_dir, f'{trial_name}_coverage_execs_summary.png')
    plt.savefig(execs_summary_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Summary plot saved as '{execs_summary_path}'")

    dual_methods = [m for m in valid_methods if "dual" in m.lower()]
    if dual_methods:
        print("\n================ Generating Corpus Imported Box Plot ================")
        plot_data = []
        plot_labels = []
        colors = []
        for method in dual_methods:
            values = []
            fuzzer_name = get_fuzzer_name(method)
            dir_method = "dual" if method.startswith("dual-") else method
            for item in trial_items:
                stats_file = os.path.join(root, item["session_dir"], dir_method, item["trial"], f"out/{fuzzer_name}/fuzzer_stats")
                val = parse_corpus_imported(stats_file)
                if val is not None:
                    values.append(val)
            if values:
                plot_data.append(values)
                label, color = get_method_info(method)
                plot_labels.append(label)
                colors.append(color)
                
        if plot_data:
            plt.figure(figsize=(8, 6))
            bp = plt.boxplot(plot_data, patch_artist=True, tick_labels=plot_labels, widths=0.4,
                             showmeans=True, meanline=True,
                             medianprops=dict(color='black', linewidth=1.5),
                             meanprops=dict(color='red', linewidth=1.5, linestyle='--'))
                             
            for i, color in enumerate(colors):
                bp['boxes'][i].set_facecolor(color)
                bp['boxes'][i].set_alpha(0.6)
                bp['boxes'][i].set_edgecolor(color)
                bp['boxes'][i].set_linewidth(1.5)
                bp['whiskers'][2*i].set_color(color)
                bp['whiskers'][2*i].set_linewidth(1.5)
                bp['whiskers'][2*i+1].set_color(color)
                bp['whiskers'][2*i+1].set_linewidth(1.5)
                bp['caps'][2*i].set_color(color)
                bp['caps'][2*i].set_linewidth(1.5)
                bp['caps'][2*i+1].set_color(color)
                bp['caps'][2*i+1].set_linewidth(1.5)
                bp['fliers'][i].set_markeredgecolor(color)
                
            for i, values in enumerate(plot_data):
                x_jitter = np.random.normal(i + 1, 0.04, size=len(values))
                plt.scatter(x_jitter, values, color=colors[i], edgecolor='black', alpha=0.8, s=45, zorder=3)
                
            plt.title(f'Corpus Imported (Dual CD+DD) Comparison ({args.cve})', fontsize=14, fontweight='bold', pad=15)
            plt.ylabel('Number of Imported Corpora', fontsize=12)
            plt.grid(True, axis='y', linestyle=':', alpha=0.6)
            plt.tight_layout()
            
            if trial_name == "all":
                boxplot_path = os.path.join(plot_base_dir, 'corpus_imported_boxplot.png')
            else:
                boxplot_path = os.path.join(plot_base_dir, f'{trial_name}_corpus_imported_boxplot.png')
            plt.savefig(boxplot_path, dpi=300, bbox_inches='tight')
            plt.close()
            print(f"Corpus imported boxplot successfully saved as '{boxplot_path}'")

if __name__ == '__main__':
    main()

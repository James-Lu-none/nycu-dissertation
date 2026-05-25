import os
import re
import argparse
import numpy as np
import matplotlib.pyplot as plt

def parse_plot_data(file_path):
    """
    Parses AFL plot_data file.
    Returns: times (list of floats), edges (list of ints), execs (list of ints)
    """
    times = []
    edges = []
    execs = []
    if not os.path.exists(file_path):
        return times, edges, execs
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
            
        header = None
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                # Extract headers
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
        print(f"Error parsing {file_path}: {e}")
        
    return times, edges, execs

def interpolate_run(times, values, common_grid):
    """
    Interpolates value series onto a common grid.
    If the grid extends beyond the last recorded point, the value remains constant.
    """
    if not times or not values:
        return np.zeros_like(common_grid)
    
    t_arr = np.array(times)
    v_arr = np.array(values)
    
    # Extend to cover the full grid range if needed
    if t_arr[-1] < common_grid[-1]:
        t_arr = np.append(t_arr, common_grid[-1])
        v_arr = np.append(v_arr, v_arr[-1])
        
    # Extend down to 0 if needed
    if t_arr[0] > common_grid[0]:
        t_arr = np.insert(t_arr, 0, common_grid[0])
        v_arr = np.insert(v_arr, 0, v_arr[1]) # Keep first value
        
    return np.interp(common_grid, t_arr, v_arr)

def geometric_mean(arrays, axis=0):
    """
    Computes geometric mean along the specified axis.
    """
    with np.errstate(divide='ignore', invalid='ignore'):
        log_data = np.log(arrays)
        mean_log = np.mean(log_data, axis=axis)
        geomean = np.exp(mean_log)
    return np.nan_to_num(geomean, nan=0.0)

def plot_single_trial(orig_time, orig_edge, orig_exec, work_time, work_edge, work_exec, output_dir, cve="CVE-2018-20427"):
    """
    Generates time-based and execution-based coverage comparison plots for a single trial.
    """
    os.makedirs(output_dir, exist_ok=True)
    
    final_orig = orig_edge[-1] if orig_edge else 0
    final_work = work_edge[-1] if work_edge else 0
    
    text_lines = []
    text_lines.append(f"Without Control: {final_orig} edges")
    text_lines.append(f"With Control: {final_work} edges")
    if final_orig > 0:
        impr = (final_work - final_orig) / final_orig * 100
        text_lines.append(f"Coverage Impr: {impr:+.1f}%")
        
    textstr = "\n".join(text_lines) if text_lines else ""
    props = dict(boxstyle='round', facecolor='#e6f2ff', alpha=0.8, edgecolor='#1f77b4')
    
    # 1. Coverage vs Time (Seconds)
    plt.figure(figsize=(10, 6))
    if orig_time:
        plt.plot(np.array(orig_time), orig_edge, label='Without Control dependency analysis', color='#1f77b4', linewidth=2)
    if work_time:
        plt.plot(np.array(work_time), work_edge, label='With Control dependency analysis', color='#ff7f0e', linewidth=2)
        
    if textstr:
        plt.text(0.05, 0.95, textstr, transform=plt.gca().transAxes, fontsize=10,
                 verticalalignment='top', bbox=props)
        
    plt.title(f'Edge Coverage Over Time ({cve})', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Elapsed Time (seconds)', fontsize=12)
    plt.ylabel('Unique Edges Found', fontsize=12)
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(loc='lower right', fontsize=10)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'coverage_time.png'), dpi=300)
    plt.close()
    
    # 2. Coverage vs Executions (Millions)
    plt.figure(figsize=(10, 6))
    if orig_exec:
        plt.plot(np.array(orig_exec) / 1e6, orig_edge, label='Without Control dependency analysis', color='#1f77b4', linewidth=2)
    if work_exec:
        plt.plot(np.array(work_exec) / 1e6, work_edge, label='With Control dependency analysis', color='#ff7f0e', linewidth=2)
        
    if textstr:
        plt.text(0.05, 0.95, textstr, transform=plt.gca().transAxes, fontsize=10,
                 verticalalignment='top', bbox=props)
        
    plt.title(f'Edge Coverage vs Total Executions ({cve})', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Total Executions (millions)', fontsize=12)
    plt.ylabel('Unique Edges Found', fontsize=12)
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(loc='lower right', fontsize=10)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'coverage_execs.png'), dpi=300)
    plt.close()

def main():
    parser = argparse.ArgumentParser(description="Generate coverage plots.")
    parser.add_argument("--root", type=str, required=True, help="Root directory of the CVE artifact data")
    parser.add_argument("--methods", type=str, nargs="+", required=True, help="Fuzzer methods to compare")
    parser.add_argument("--trials", type=str, nargs="+", required=True, help="Trial numbers")
    parser.add_argument("--cve", type=str, default="CVE-2018-20427", help="CVE identifier")
    args = parser.parse_args()
    
    root = os.path.expanduser(args.root)
    baseline_dir_name = args.methods[0]
    icd_dir_name = args.methods[1]
    
    base_dir = os.path.join(root, baseline_dir_name)
    control_dir = os.path.join(root, icd_dir_name)
    plot_base_dir = os.path.join(root, "plot")
    
    if not os.path.exists(base_dir):
        print(f"Base directory {base_dir} does not exist.")
        return
        
    # Standardize trial folder names, e.g. trial1, trial2...
    trials = ["trial" + t for t in args.trials]
    # Sort natural order
    trials.sort(key=lambda x: int(re.search(r'\d+', x).group()) if re.search(r'\d+', x) else x)
    
    print(f"Using base_dir: {base_dir}")
    print(f"Using control_dir: {control_dir}")
    print(f"Found trials for coverage plotting: {trials}")
    
    orig_runs_time = []
    work_runs_time = []
    orig_runs_exec = []
    work_runs_exec = []
    
    max_time_all = 0
    max_exec_all = 0
    
    for trial in trials:
        print(f"\n================ Processing Coverage for {trial} ================")
        orig_plot_file = os.path.join(base_dir, trial, "out/main/plot_data")
        work_plot_file = os.path.join(control_dir, trial, "out/main/plot_data")
        
        orig_time, orig_edge, orig_exec = parse_plot_data(orig_plot_file)
        work_time, work_edge, work_exec = parse_plot_data(work_plot_file)
        
        output_dir = os.path.join(plot_base_dir, trial)
        
        print(f"Plotting single-trial coverage to {output_dir}...")
        plot_single_trial(orig_time, orig_edge, orig_exec, work_time, work_edge, work_exec, output_dir, cve=args.cve)
        
        # Save for summary averaging
        if orig_time:
            orig_runs_time.append((orig_time, orig_edge))
            orig_runs_exec.append((orig_exec, orig_edge))
            max_time_all = max(max_time_all, orig_time[-1])
            max_exec_all = max(max_exec_all, orig_exec[-1])
            
        if work_time:
            work_runs_time.append((work_time, work_edge))
            work_runs_exec.append((work_exec, work_edge))
            max_time_all = max(max_time_all, work_time[-1])
            max_exec_all = max(max_exec_all, work_exec[-1])
            
    # Generate overall summary average plots if we have runs
    if orig_runs_time or work_runs_time:
        print("\n================ Generating Coverage Summary Plots ================")
        os.makedirs(plot_base_dir, exist_ok=True)
        
        # 1. Summary plot over Time (Hours)
        common_times = np.linspace(0, max_time_all, num=1000)
        
        orig_interp_time = []
        for times, edges in orig_runs_time:
            orig_interp_time.append(interpolate_run(times, edges, common_times))
            
        work_interp_time = []
        for times, edges in work_runs_time:
            work_interp_time.append(interpolate_run(times, edges, common_times))
            
        plt.figure(figsize=(10, 6))
        
        # Plot individual lines as faint lines
        for i, interp in enumerate(orig_interp_time):
            lbl = 'Without Control (individual)' if i == 0 else ""
            plt.plot(common_times, interp, color='#1f77b4', alpha=0.25, linewidth=1, label=lbl)
            
        for i, interp in enumerate(work_interp_time):
            lbl = 'With Control (individual)' if i == 0 else ""
            plt.plot(common_times, interp, color='#ff7f0e', alpha=0.25, linewidth=1, label=lbl)
            
        # Plot mean and std area
        if orig_interp_time:
            orig_mean = geometric_mean(orig_interp_time, axis=0)
            orig_std = np.std(orig_interp_time, axis=0)
            plt.plot(common_times, orig_mean, color='#1f77b4', linewidth=2.5, label='Without Control (average)')
            plt.fill_between(common_times, np.maximum(0, orig_mean - orig_std), orig_mean + orig_std, color='#1f77b4', alpha=0.12)
            
        if work_interp_time:
            work_mean = geometric_mean(work_interp_time, axis=0)
            work_std = np.std(work_interp_time, axis=0)
            plt.plot(common_times, work_mean, color='#ff7f0e', linewidth=2.5, label='With Control (average)')
            plt.fill_between(common_times, np.maximum(0, work_mean - work_std), work_mean + work_std, color='#ff7f0e', alpha=0.12)
            
        text_lines = []
        if orig_interp_time and work_interp_time:
            final_orig_avg = orig_mean[-1]
            final_work_avg = work_mean[-1]
            text_lines.append(f"Avg Without Control: {final_orig_avg:.1f} edges")
            text_lines.append(f"Avg With Control: {final_work_avg:.1f} edges")
            if final_orig_avg > 0:
                impr = (final_work_avg - final_orig_avg) / final_orig_avg * 100
                text_lines.append(f"Avg Coverage Impr: {impr:+.1f}%")
                
        if text_lines:
            textstr = "\n".join(text_lines)
            props = dict(boxstyle='round', facecolor='#e6f2ff', alpha=0.8, edgecolor='#1f77b4')
            plt.text(0.05, 0.95, textstr, transform=plt.gca().transAxes, fontsize=10,
                     verticalalignment='top', bbox=props, fontweight='bold')
                     
        plt.title(f'Edge Coverage Over Time ({args.cve})', fontsize=14, fontweight='bold', pad=15)
        plt.xlabel('Elapsed Time (seconds)', fontsize=12)
        plt.ylabel('Unique Edges Found', fontsize=12)
        plt.grid(True, linestyle=':', alpha=0.6)
        plt.legend(loc='lower right', fontsize=10)
        plt.tight_layout()
        plt.savefig(os.path.join(plot_base_dir, 'coverage_time_summary.png'), dpi=300)
        plt.close()
        print(f"Summary plot saved as '{os.path.join(plot_base_dir, 'coverage_time_summary.png')}'")
        
        # 2. Summary plot over Executions (Millions)
        common_execs = np.linspace(0, max_exec_all, num=1000)
        
        orig_interp_exec = []
        for execs, edges in orig_runs_exec:
            orig_interp_exec.append(interpolate_run(execs, edges, common_execs))
            
        work_interp_exec = []
        for execs, edges in work_runs_exec:
            work_interp_exec.append(interpolate_run(execs, edges, common_execs))
            
        plt.figure(figsize=(10, 6))
        
        # Plot individual lines as faint lines
        for i, interp in enumerate(orig_interp_exec):
            lbl = 'Without Control (individual)' if i == 0 else ""
            plt.plot(common_execs / 1e6, interp, color='#1f77b4', alpha=0.25, linewidth=1, label=lbl)
            
        for i, interp in enumerate(work_interp_exec):
            lbl = 'With Control (individual)' if i == 0 else ""
            plt.plot(common_execs / 1e6, interp, color='#ff7f0e', alpha=0.25, linewidth=1, label=lbl)
            
        # Plot mean and std area
        if orig_interp_exec:
            orig_mean_exec = geometric_mean(orig_interp_exec, axis=0)
            orig_std_exec = np.std(orig_interp_exec, axis=0)
            plt.plot(common_execs / 1e6, orig_mean_exec, color='#1f77b4', linewidth=2.5, label='Without Control (average)')
            plt.fill_between(common_execs / 1e6, np.maximum(0, orig_mean_exec - orig_std_exec), orig_mean_exec + orig_std_exec, color='#1f77b4', alpha=0.12)
            
        if work_interp_exec:
            work_mean_exec = geometric_mean(work_interp_exec, axis=0)
            work_std_exec = np.std(work_interp_exec, axis=0)
            plt.plot(common_execs / 1e6, work_mean_exec, color='#ff7f0e', linewidth=2.5, label='With Control (average)')
            plt.fill_between(common_execs / 1e6, np.maximum(0, work_mean_exec - work_std_exec), work_mean_exec + work_std_exec, color='#ff7f0e', alpha=0.12)
            
        text_lines = []
        if orig_interp_exec and work_interp_exec:
            final_orig_avg = orig_mean_exec[-1]
            final_work_avg = work_mean_exec[-1]
            text_lines.append(f"Avg Without Control: {final_orig_avg:.1f} edges")
            text_lines.append(f"Avg With Control: {final_work_avg:.1f} edges")
            if final_orig_avg > 0:
                impr = (final_work_avg - final_orig_avg) / final_orig_avg * 100
                text_lines.append(f"Avg Coverage Impr: {impr:+.1f}%")
                
        if text_lines:
            textstr = "\n".join(text_lines)
            props = dict(boxstyle='round', facecolor='#e6f2ff', alpha=0.8, edgecolor='#1f77b4')
            plt.text(0.05, 0.95, textstr, transform=plt.gca().transAxes, fontsize=10,
                     verticalalignment='top', bbox=props, fontweight='bold')
                     
        plt.title(f'Edge Coverage vs Total Executions ({args.cve})', fontsize=14, fontweight='bold', pad=15)
        plt.xlabel('Total Executions (millions)', fontsize=12)
        plt.ylabel('Unique Edges Found', fontsize=12)
        plt.grid(True, linestyle=':', alpha=0.6)
        plt.legend(loc='lower right', fontsize=10)
        plt.tight_layout()
        plt.savefig(os.path.join(plot_base_dir, 'coverage_execs_summary.png'), dpi=300)
        plt.close()
        print(f"Summary plot saved as '{os.path.join(plot_base_dir, 'coverage_execs_summary.png')}'")

if __name__ == '__main__':
    main()

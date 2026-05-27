import os
import re
import argparse
import numpy as np
import matplotlib.pyplot as plt

def parse_target_reached(file_path):
    """
    Parses dgf_target_reached.txt to get the elapsed time in seconds.
    """
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            match = re.search(r'Elapsed:\s+([\d\.]+)\s+seconds', content)
            if match:
                return float(match.group(1))
            match_ms = re.search(r'\((\d+)\s*ms\)', content)
            if match_ms:
                return float(match_ms.group(1)) / 1000.0
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
    return None

def parse_blocks_hit_cumulative(file_path, limit_time=None):
    """
    Parses dgf_blocks_hit.txt and returns lists of (seconds, cumulative_hits)
    """
    if not os.path.exists(file_path):
        return [], []
    
    events = []
    try:
        with open(file_path, 'r') as f:
            header = f.readline()
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(',')
                if len(parts) != 3:
                    continue
                btype, bid, elapsed_ms = int(parts[0]), int(parts[1]), int(parts[2])
                sec = elapsed_ms / 1000.0
                if limit_time is not None and sec > limit_time:
                    continue
                events.append((sec, (btype, bid)))
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
        return [], []
    
    events.sort(key=lambda x: x[0])
    
    times = [0.0]
    counts = [0]
    seen_blocks = set()
    
    for sec, block in events:
        if block not in seen_blocks:
            seen_blocks.add(block)
            times.append(sec)
            counts.append(len(seen_blocks))
            
    # Add a final point at limit_time to extend the line flat to the target reached time
    if limit_time is not None and (not times or times[-1] < limit_time):
        times.append(limit_time)
        counts.append(counts[-1] if counts else 0)
        
    return times, counts

def parse_dgf_log_raw(filepath, limit_time=None):
    """
    Parses dgf_blocks_hit.txt and returns raw hit times: dict of {id: elapsed_ms}
    """
    control_hits = {}
    caller_hits = {}
    if not os.path.exists(filepath):
        return control_hits, caller_hits
    try:
        with open(filepath, 'r') as f:
            f.readline()  # Skip header
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(',')
                if len(parts) != 3:
                    continue
                btype, bid, elapsed_ms = int(parts[0]), int(parts[1]), int(parts[2])
                if limit_time is not None and (elapsed_ms / 1000.0) > limit_time:
                    continue
                if btype == 0:
                    if bid not in control_hits:
                        control_hits[bid] = elapsed_ms
                elif btype == 1:
                    if bid not in caller_hits:
                        caller_hits[bid] = elapsed_ms
    except Exception as e:
        print(f"Error parsing raw {filepath}: {e}")
    return control_hits, caller_hits

def find_target_id_and_type(block_mapping_path):
    """
    Searches dgf_block_mapping.txt for the target function 'decompileSETPROPERTY'
    to retrieve its Block ID and Type (Control/Caller).
    """
    if not os.path.exists(block_mapping_path):
        return None, None
    try:
        with open(block_mapping_path, 'r') as f:
            f.readline()  # skip header
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(',')
                if len(parts) >= 4:
                    bid = int(parts[0])
                    btype = parts[1].strip()
                    func = parts[2].strip()
                    if func == "decompileSETPROPERTY":
                        return bid, btype
    except Exception as e:
        print(f"Error parsing block mapping file: {e}")
    return None, None

def generate_cumulative_plot(orig_hit_file, orig_reached_file, work_hit_file, work_reached_file, use_ttr_limit, output_filename, total_blocks=None, cve="CVE-2018-20427"):
    orig_target_time = parse_target_reached(orig_reached_file) if use_ttr_limit else None
    work_target_time = parse_target_reached(work_reached_file) if use_ttr_limit else None
    
    orig_times, orig_counts = parse_blocks_hit_cumulative(orig_hit_file, limit_time=orig_target_time)
    work_times, work_counts = parse_blocks_hit_cumulative(work_hit_file, limit_time=work_target_time)
    
    plt.figure(figsize=(10, 6))
    plt.step(orig_times, orig_counts, where='post', label='Without Control dependency analysis', color='#1f77b4', linewidth=2)
    plt.step(work_times, work_counts, where='post', label='With Control dependency analysis', color='#ff7f0e', linewidth=2)
    
    actual_orig_reached = parse_target_reached(orig_reached_file)
    actual_work_reached = parse_target_reached(work_reached_file)
    
    if actual_orig_reached:
        plt.axvline(x=actual_orig_reached, color='#1f77b4', linestyle='--', alpha=0.8,
                    label=f'Without Control Reached ({actual_orig_reached:.2f}s)')
    if actual_work_reached:
        plt.axvline(x=actual_work_reached, color='#ff7f0e', linestyle='--', alpha=0.8,
                    label=f'With Control Reached ({actual_work_reached:.2f}s)')
        
    text_lines = []
    if actual_orig_reached and actual_work_reached:
        speedup = actual_orig_reached / actual_work_reached
        time_saved = (actual_orig_reached - actual_work_reached) / actual_orig_reached * 100
        text_lines.append(f"TTR Speedup: {speedup:.2f}x")
        text_lines.append(f"Time Saved: {time_saved:.1f}%")
        
    if orig_counts and work_counts:
        final_orig_blocks = orig_counts[-1]
        final_work_blocks = work_counts[-1]
        if total_blocks:
            orig_pct = final_orig_blocks / total_blocks * 100
            work_pct = final_work_blocks / total_blocks * 100
            text_lines.append(f"Without Control Blocks: {final_orig_blocks} ({orig_pct:.1f}%)")
            text_lines.append(f"With Control Blocks: {final_work_blocks} ({work_pct:.1f}%)")
        else:
            text_lines.append(f"Without Control Blocks: {final_orig_blocks}")
            text_lines.append(f"With Control Blocks: {final_work_blocks}")
        if final_orig_blocks > 0:
            block_improvement = (final_work_blocks - final_orig_blocks) / final_orig_blocks * 100
            text_lines.append(f"Blocks Hit Impr: {block_improvement:+.1f}%")
            
    if not use_ttr_limit and total_blocks is not None:
        text_lines.append(f"Total Unique Blocks: {total_blocks}")
            
    if text_lines:
        textstr = "\n".join(text_lines)
        props = dict(boxstyle='round', facecolor='#e6f2ff', alpha=0.8, edgecolor='#1f77b4')
        plt.text(1.02, 1.0, textstr, transform=plt.gca().transAxes, fontsize=10,
                  verticalalignment='top', bbox=props)
                  
    title_suffix = " (Up to Target Reached)" if use_ttr_limit else " (Full Run)"
    plt.title(f'Time to Reach Target (TTR) and Unique Blocks Hit Comparison ({cve})' + title_suffix, fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Elapsed Time (seconds)', fontsize=12)
    plt.ylabel('Cumulative Unique Basic Blocks Hit', fontsize=12)
    
    if use_ttr_limit:
        max_target_time = max(filter(None, [actual_orig_reached, actual_work_reached]), default=None)
        if max_target_time:
            plt.xlim(0, max_target_time * 1.05)
    else:
        all_times = orig_times + work_times
        if all_times:
            plt.xlim(0, max(all_times) * 1.05)
            
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(loc='best', fontsize=10)
    plt.tight_layout()
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Comparison plot successfully saved as '{output_filename}'")

def parse_block_mapping_ids(block_mapping_path):
    """
    Parses dgf_block_mapping.txt to get all control and caller block IDs.
    """
    control_ids = []
    caller_ids = []
    if not os.path.exists(block_mapping_path):
        return control_ids, caller_ids
    try:
        with open(block_mapping_path, 'r') as f:
            f.readline()  # skip header
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(',')
                if len(parts) >= 2:
                    try:
                        bid = int(parts[0])
                        btype = parts[1].strip()
                        if btype == 'Control':
                            control_ids.append(bid)
                        elif btype == 'Caller':
                            caller_ids.append(bid)
                    except ValueError:
                        continue
    except Exception as e:
        print(f"Error parsing mapping IDs from {block_mapping_path}: {e}")
    return control_ids, caller_ids

def generate_bar_plot(orig_hit_file, orig_reached_file, work_hit_file, work_reached_file, work_mapping_file, use_ttr_limit, output_filename, cve="CVE-2018-20427"):
    orig_target_time = parse_target_reached(orig_reached_file) if use_ttr_limit else None
    work_target_time = parse_target_reached(work_reached_file) if use_ttr_limit else None
    
    orig_ctrl, orig_call = parse_dgf_log_raw(orig_hit_file, limit_time=orig_target_time)
    work_ctrl, work_call = parse_dgf_log_raw(work_hit_file, limit_time=work_target_time)
    
    target_id, target_type = find_target_id_and_type(work_mapping_file)
    if target_id is not None:
        print(f"Target block detected: ID={target_id}, Type={target_type}")
    
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 10))
    width = 0.35
    
    # Filter Control BBs (Type 0) to only include those hit by at least one group
    mapped_ctrl, mapped_call = parse_block_mapping_ids(work_mapping_file)
    if mapped_ctrl:
        max_ctrl_val = max(mapped_ctrl)
    else:
        max_ctrl_val = max(list(orig_ctrl.keys()) + list(work_ctrl.keys()) + [145])
        
    control_ids = [i for i in range(max_ctrl_val + 1) if i in orig_ctrl or i in work_ctrl]
    control_ids.sort(key=lambda bid: (
        0 if bid in orig_ctrl else 1,
        orig_ctrl.get(bid, 0.0) if bid in orig_ctrl else work_ctrl.get(bid, 0.0)
    ))
    
    orig_ctrl_times = [orig_ctrl.get(i, 0.0) / 1000.0 for i in control_ids]
    work_ctrl_times = [work_ctrl.get(i, 0.0) / 1000.0 for i in control_ids]
    
    x_indices_ctrl = list(range(len(control_ids)))
    # Bars kept at original distinct colors (Blue and Orange)
    ax1.bar([x - width/2 for x in x_indices_ctrl], orig_ctrl_times, width, label='Without Control dependency analysis', color='#1f77b4')
    ax1.bar([x + width/2 for x in x_indices_ctrl], work_ctrl_times, width, label='With Control dependency analysis', color='#ff7f0e')
    
    # Draw vertical dashed line for Target if in Control BBs
    if target_id is not None and target_type == 'Control' and target_id in control_ids:
        target_idx = control_ids.index(target_id)
        ax1.axvline(x=target_idx, color='#d62728', linestyle='--', linewidth=1.8, alpha=0.9, label=f'Target Block (ID {target_id})')
    
    title_suffix = " (Before Target Reached)" if use_ttr_limit else " (Full Run)"
    ax1.set_title(f'Control BBs (Type 0) First Hit Time (Sorted by Blue\'s Hit Time) ({cve})' + title_suffix, fontsize=14, fontweight='bold')
    ax1.set_xlabel('Control Block ID', fontsize=11)
    ax1.set_ylabel('Hit Time (seconds)', fontsize=11)
    ax1.set_xticks(x_indices_ctrl)
    ax1.set_xticklabels([f"{bid}\n(Target)" if (bid == target_id and target_type == 'Control') else str(bid) for bid in control_ids], rotation=45, fontsize=8)
    ax1.grid(True, axis='y', linestyle=':', alpha=0.6)
    ax1.legend(loc='upper right')
    
    # Filter Caller BBs (Type 1) to only include those hit by at least one group
    if mapped_call:
        max_call_val = max(mapped_call)
    else:
        max_call_val = max(list(orig_call.keys()) + list(work_call.keys()) + [40])
        
    caller_ids = [i for i in range(max_call_val + 1) if i in orig_call or i in work_call]
    caller_ids.sort(key=lambda bid: (
        0 if bid in orig_call else 1,
        orig_call.get(bid, 0.0) if bid in orig_call else work_call.get(bid, 0.0)
    ))
    
    orig_call_times = [orig_call.get(i, 0.0) / 1000.0 for i in caller_ids]
    work_call_times = [work_call.get(i, 0.0) / 1000.0 for i in caller_ids]
    
    x_indices_call = list(range(len(caller_ids)))
    ax2.bar([x - width/2 for x in x_indices_call], orig_call_times, width, label='Without Control dependency analysis', color='#1f77b4')
    ax2.bar([x + width/2 for x in x_indices_call], work_call_times, width, label='With Control dependency analysis', color='#ff7f0e')
    
    # Draw vertical dashed line for Target if in Caller BBs
    if target_id is not None and target_type == 'Caller' and target_id in caller_ids:
        target_idx = caller_ids.index(target_id)
        ax2.axvline(x=target_idx, color='#d62728', linestyle='--', linewidth=1.8, alpha=0.9, label=f'Target Block (ID {target_id})')
    
    ax2.set_title(f'Caller BBs (Type 1) First Hit Time (Sorted by Blue\'s Hit Time) ({cve})' + title_suffix, fontsize=14, fontweight='bold')
    ax2.set_xlabel('Caller Block ID', fontsize=11)
    ax2.set_ylabel('Hit Time (seconds)', fontsize=11)
    ax2.set_xticks(x_indices_call)
    ax2.set_xticklabels([f"{bid}\n(Target)" if (bid == target_id and target_type == 'Caller') else str(bid) for bid in caller_ids], rotation=45, fontsize=8)
    ax2.grid(True, axis='y', linestyle=':', alpha=0.6)
    ax2.legend(loc='upper right')
    
    plt.tight_layout()
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Bar comparison plot successfully saved as '{output_filename}'")

def interpolate_run(times, counts, common_times):
    """
    Interpolates cumulative hit counts onto common_times.
    Extends the last count flat if common_times goes beyond times.
    """
    if not times:
        return np.zeros_like(common_times)
    
    t_arr = np.array(times)
    c_arr = np.array(counts)
    
    # Extend to common_times[-1] if needed
    if t_arr[-1] < common_times[-1]:
        t_arr = np.append(t_arr, common_times[-1])
        c_arr = np.append(c_arr, c_arr[-1])
        
    # Extend down to 0 if needed
    if t_arr[0] > common_times[0]:
        t_arr = np.insert(t_arr, 0, common_times[0])
        c_arr = np.insert(c_arr, 0, 0)
        
    return np.interp(common_times, t_arr, c_arr)

def geometric_mean(arrays, axis=0):
    """
    Computes geometric mean along the specified axis.
    """
    with np.errstate(divide='ignore', invalid='ignore'):
        log_data = np.log(arrays)
        mean_log = np.mean(log_data, axis=axis)
        geomean = np.exp(mean_log)
    return np.nan_to_num(geomean, nan=0.0)

def generate_cumulative_summary_plot(orig_runs, orig_reached_times, work_runs, work_reached_times, use_ttr_limit, output_filename, total_blocks=None, cve="CVE-2018-20427"):
    """
    orig_runs: list of tuples (times, counts)
    orig_reached_times: list of floats/None
    work_runs: list of tuples (times, counts)
    work_reached_times: list of floats/None
    """
    orig_runs = [r for r in orig_runs if r[0]]
    work_runs = [r for r in work_runs if r[0]]
    
    if not orig_runs and not work_runs:
        print("No runs data available for TTR summary plot.")
        return
        
    # Determine the maximum time point to plot
    all_times = []
    for times, _ in orig_runs:
        all_times.extend(times)
    for times, _ in work_runs:
        all_times.extend(times)
        
    if not all_times:
        return
        
    max_time = max(all_times)
    common_times = np.linspace(0, max_time, num=1000)
    
    # Interpolate all runs
    orig_interp = [interpolate_run(r[0], r[1], common_times) for r in orig_runs]
    work_interp = [interpolate_run(r[0], r[1], common_times) for r in work_runs]
    
    plt.figure(figsize=(10, 6))
    
    # Plot individual runs as thin, semi-transparent lines
    for i, interp in enumerate(orig_interp):
        lbl = 'Without Control (individual)' if i == 0 else ""
        plt.plot(common_times, interp, color='#1f77b4', alpha=0.25, linewidth=1, label=lbl)
        
    for i, interp in enumerate(work_interp):
        lbl = 'With Control (individual)' if i == 0 else ""
        plt.plot(common_times, interp, color='#ff7f0e', alpha=0.25, linewidth=1, label=lbl)
        
    # Plot mean curves
    if orig_interp:
        orig_mean = geometric_mean(orig_interp, axis=0)
        orig_std = np.std(orig_interp, axis=0)
        plt.step(common_times, orig_mean, where='post', color='#1f77b4', linewidth=2.5, label='Without Control (average)')
        plt.fill_between(common_times, np.maximum(0, orig_mean - orig_std), orig_mean + orig_std, color='#1f77b4', alpha=0.12, step='post')
        
    if work_interp:
        work_mean = geometric_mean(work_interp, axis=0)
        work_std = np.std(work_interp, axis=0)
        plt.step(common_times, work_mean, where='post', color='#ff7f0e', linewidth=2.5, label='With Control (average)')
        plt.fill_between(common_times, np.maximum(0, work_mean - work_std), work_mean + work_std, color='#ff7f0e', alpha=0.12, step='post')
        
    # Add vertical lines for mean reached times
    valid_orig_reached = [t for t in orig_reached_times if t is not None]
    valid_work_reached = [t for t in work_reached_times if t is not None]
    
    if valid_orig_reached:
        mean_orig_reached = np.exp(np.mean(np.log(valid_orig_reached)))
        plt.axvline(x=mean_orig_reached, color='#1f77b4', linestyle='--', alpha=0.8,
                    label=f'Without Control Reached Geo Mean ({mean_orig_reached:.2f}s)')
                    
    if valid_work_reached:
        mean_work_reached = np.exp(np.mean(np.log(valid_work_reached)))
        plt.axvline(x=mean_work_reached, color='#ff7f0e', linestyle='--', alpha=0.8,
                    label=f'With Control Reached Geo Mean ({mean_work_reached:.2f}s)')
                    
    text_lines = []
    if valid_orig_reached and valid_work_reached:
        mean_orig = np.exp(np.mean(np.log(valid_orig_reached)))
        mean_work = np.exp(np.mean(np.log(valid_work_reached)))
        speedup = mean_orig / mean_work
        time_saved = (mean_orig - mean_work) / mean_orig * 100
        text_lines.append(f"Avg TTR Speedup: {speedup:.2f}x")
        text_lines.append(f"Avg Time Saved: {time_saved:.1f}%")
        
    if orig_interp and work_interp:
        final_orig_avg = orig_mean[-1]
        final_work_avg = work_mean[-1]
        if total_blocks:
            orig_pct = final_orig_avg / total_blocks * 100
            work_pct = final_work_avg / total_blocks * 100
            text_lines.append(f"Avg Without Control Blocks: {final_orig_avg:.1f} ({orig_pct:.1f}%)")
            text_lines.append(f"Avg With Control Blocks: {final_work_avg:.1f} ({work_pct:.1f}%)")
        else:
            text_lines.append(f"Avg Without Control Blocks: {final_orig_avg:.1f}")
            text_lines.append(f"Avg With Control Blocks: {final_work_avg:.1f}")
        if final_orig_avg > 0:
            block_improvement = (final_work_avg - final_orig_avg) / final_orig_avg * 100
            text_lines.append(f"Avg Blocks Hit Impr: {block_improvement:+.1f}%")
            
    if not use_ttr_limit and total_blocks is not None:
        text_lines.append(f"Total Unique Blocks: {total_blocks}")
            
    if text_lines:
        textstr = "\n".join(text_lines)
        props = dict(boxstyle='round', facecolor='#e6f2ff', alpha=0.8, edgecolor='#1f77b4')
        plt.text(1.02, 1.0, textstr, transform=plt.gca().transAxes, fontsize=11,
                  verticalalignment='top', bbox=props, fontweight='bold')
                  
    title_suffix = " (Up to Target Reached)" if use_ttr_limit else " (Full Run)"
    plt.title(f'Time to Reach Target (TTR) and Unique Blocks Hit Summary ({cve})' + title_suffix, fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Elapsed Time (seconds)', fontsize=12)
    plt.ylabel('Cumulative Unique Basic Blocks Hit', fontsize=12)
    
    plt.xlim(0, max_time * 1.05)
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(loc='best', fontsize=10)
    plt.tight_layout()
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Summary plot successfully saved as '{output_filename}'")

def geometric_mean_of_list(vals):
    if not vals:
        return 0.0
    vals = np.array(vals)
    vals = vals[vals > 0]
    if len(vals) == 0:
        return 0.0
    return np.exp(np.mean(np.log(vals)))

def generate_bar_summary_plot(orig_runs_raw, work_runs_raw, work_mapping_file, use_ttr_limit, output_filename, cve="CVE-2018-20427"):
    """
    orig_runs_raw: list of tuples (orig_ctrl, orig_call) from parse_dgf_log_raw for each trial
    work_runs_raw: list of tuples (work_ctrl, work_call) from parse_dgf_log_raw for each trial
    """
    orig_ctrls = [run[0] for run in orig_runs_raw]
    orig_calls = [run[1] for run in orig_runs_raw]
    work_ctrls = [run[0] for run in work_runs_raw]
    work_calls = [run[1] for run in work_runs_raw]
    
    mapped_ctrl, mapped_call = parse_block_mapping_ids(work_mapping_file)
    if mapped_ctrl:
        max_ctrl_val = max(mapped_ctrl)
    else:
        all_ctrl_keys = []
        for run in orig_ctrls + work_ctrls:
            all_ctrl_keys.extend(run.keys())
        max_ctrl_val = max(all_ctrl_keys) if all_ctrl_keys else 145
        
    control_ids = []
    for bid in range(max_ctrl_val + 1):
        hit_in_orig = any(bid in orig_ctrl for orig_ctrl in orig_ctrls)
        hit_in_work = any(bid in work_ctrl for work_ctrl in work_ctrls)
        if hit_in_orig or hit_in_work:
            control_ids.append(bid)
            
    # Sort Control BBs
    control_ids.sort(key=lambda bid: (
        0 if any(bid in orig_ctrl for orig_ctrl in orig_ctrls) else 1,
        geometric_mean_of_list([orig_ctrl[bid] / 1000.0 for orig_ctrl in orig_ctrls if bid in orig_ctrl]) 
        if any(bid in orig_ctrl for orig_ctrl in orig_ctrls) else 
        geometric_mean_of_list([work_ctrl[bid] / 1000.0 for work_ctrl in work_ctrls if bid in work_ctrl])
    ))
    
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 10))
    width = 0.35
    
    orig_ctrl_times = [geometric_mean_of_list([orig_ctrl[bid] / 1000.0 for orig_ctrl in orig_ctrls if bid in orig_ctrl]) for bid in control_ids]
    work_ctrl_times = [geometric_mean_of_list([work_ctrl[bid] / 1000.0 for work_ctrl in work_ctrls if bid in work_ctrl]) for bid in control_ids]
    
    x_indices_ctrl = list(range(len(control_ids)))
    ax1.bar([x - width/2 for x in x_indices_ctrl], orig_ctrl_times, width, label='Without Control dependency analysis (Geo Mean)', color='#1f77b4')
    ax1.bar([x + width/2 for x in x_indices_ctrl], work_ctrl_times, width, label='With Control dependency analysis (Geo Mean)', color='#ff7f0e')
    
    target_id, target_type = find_target_id_and_type(work_mapping_file)
    if target_id is not None and target_type == 'Control' and target_id in control_ids:
        target_idx = control_ids.index(target_id)
        ax1.axvline(x=target_idx, color='#d62728', linestyle='--', linewidth=1.8, alpha=0.9, label=f'Target Block (ID {target_id})')
        
    title_suffix = " (Before Target Reached)" if use_ttr_limit else " (Full Run)"
    ax1.set_title(f'Control BBs (Type 0) First Hit Time Summary (Geometric Mean) ({cve})' + title_suffix, fontsize=14, fontweight='bold')
    ax1.set_ylabel('Hit Time (seconds)', fontsize=11)
    ax1.set_xticks(x_indices_ctrl)
    ax1.set_xticklabels([f"{bid}\n(Target)" if (bid == target_id and target_type == 'Control') else str(bid) for bid in control_ids], rotation=45, fontsize=8)
    ax1.grid(True, axis='y', linestyle=':', alpha=0.6)
    ax1.legend(loc='upper right')
    
    # Caller BBs
    if mapped_call:
        max_call_val = max(mapped_call)
    else:
        all_call_keys = []
        for run in orig_calls + work_calls:
            all_call_keys.extend(run.keys())
        max_call_val = max(all_call_keys) if all_call_keys else 40
        
    caller_ids = []
    for bid in range(max_call_val + 1):
        hit_in_orig = any(bid in orig_call for orig_call in orig_calls)
        hit_in_work = any(bid in work_call for work_call in work_calls)
        if hit_in_orig or hit_in_work:
            caller_ids.append(bid)
            
    # Sort Caller BBs
    caller_ids.sort(key=lambda bid: (
        0 if any(bid in orig_call for orig_call in orig_calls) else 1,
        geometric_mean_of_list([orig_call[bid] / 1000.0 for orig_call in orig_calls if bid in orig_call])
        if any(bid in orig_call for orig_call in orig_calls) else
        geometric_mean_of_list([work_call[bid] / 1000.0 for work_call in work_calls if bid in work_call])
    ))
    
    orig_call_times = [geometric_mean_of_list([orig_call[bid] / 1000.0 for orig_call in orig_calls if bid in orig_call]) for bid in caller_ids]
    work_call_times = [geometric_mean_of_list([work_call[bid] / 1000.0 for work_call in work_calls if bid in work_call]) for bid in caller_ids]
    
    x_indices_call = list(range(len(caller_ids)))
    ax2.bar([x - width/2 for x in x_indices_call], orig_call_times, width, label='Without Control dependency analysis (Geo Mean)', color='#1f77b4')
    ax2.bar([x + width/2 for x in x_indices_call], work_call_times, width, label='With Control dependency analysis (Geo Mean)', color='#ff7f0e')
    
    if target_id is not None and target_type == 'Caller' and target_id in caller_ids:
        target_idx = caller_ids.index(target_id)
        ax2.axvline(x=target_idx, color='#d62728', linestyle='--', linewidth=1.8, alpha=0.9, label=f'Target Block (ID {target_id})')
        
    ax2.set_title(f'Caller BBs (Type 1) First Hit Time Summary (Geometric Mean) ({cve})' + title_suffix, fontsize=14, fontweight='bold')
    ax2.set_xlabel('Caller Block ID', fontsize=11)
    ax2.set_ylabel('Hit Time (seconds)', fontsize=11)
    ax2.set_xticks(x_indices_call)
    ax2.set_xticklabels([f"{bid}\n(Target)" if (bid == target_id and target_type == 'Caller') else str(bid) for bid in caller_ids], rotation=45, fontsize=8)
    ax2.grid(True, axis='y', linestyle=':', alpha=0.6)
    ax2.legend(loc='upper right')
    
    plt.tight_layout()
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Bar summary plot successfully saved as '{output_filename}'")

def parse_total_unique_blocks(compile_info_path):
    """
    Parses dgf_compile_info.txt to retrieve the sum of Control BBs and Caller BBs (point 1).
    """
    if not os.path.exists(compile_info_path):
        return None
    control_bbs = None
    caller_bbs = None
    try:
        with open(compile_info_path, 'r') as f:
            for line in f:
                if "Number of Control BBs" in line:
                    match = re.search(r'Number of Control BBs.*:\s+(\d+)', line)
                    if match:
                        control_bbs = int(match.group(1))
                if "Number of Caller BBs" in line:
                    match = re.search(r'Number of Caller BBs.*:\s+(\d+)', line)
                    if match:
                        caller_bbs = int(match.group(1))
        if control_bbs is not None and caller_bbs is not None:
            return control_bbs + caller_bbs
    except Exception as e:
        print(f"Error parsing compile info file: {e}")
    return None

def main():
    parser = argparse.ArgumentParser(description="Generate TTR plots.")
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
    
    # Parse total unique blocks from first trial compile info
    compile_info_path = os.path.join(control_dir, trials[0], "dgf_compile_info.txt")
    total_blocks = parse_total_unique_blocks(compile_info_path)
    if total_blocks:
        print(f"Parsed total unique blocks: {total_blocks}")
    else:
        # Try baseline dir
        compile_info_path_base = os.path.join(base_dir, trials[0], "dgf_compile_info.txt")
        total_blocks = parse_total_unique_blocks(compile_info_path_base)
        if total_blocks:
            print(f"Parsed total unique blocks: {total_blocks}")
            
    print(f"Using base_dir: {base_dir}")
    print(f"Using control_dir: {control_dir}")
    print(f"Found trials: {trials}")
    
    # Containers for summary plots
    orig_runs_limit = []
    orig_runs_full = []
    work_runs_limit = []
    work_runs_full = []
    
    orig_reached_times = []
    work_reached_times = []
    
    orig_raw_limit = []
    work_raw_limit = []
    orig_raw_full = []
    work_raw_full = []
    
    for trial in trials:
        print(f"\n================ Processing {trial} ================")
        orig_dir = os.path.join(base_dir, trial)
        work_dir = os.path.join(control_dir, trial)
        
        orig_hit_file = os.path.join(orig_dir, "dgf_blocks_hit.txt")
        orig_reached_file = os.path.join(orig_dir, "dgf_target_reached.txt")
        
        work_hit_file = os.path.join(work_dir, "dgf_blocks_hit.txt")
        work_reached_file = os.path.join(work_dir, "dgf_target_reached.txt")
        work_mapping_file = os.path.join(work_dir, "dgf_block_mapping.txt")
        
        output_dir = os.path.join(plot_base_dir, trial)
        os.makedirs(output_dir, exist_ok=True)
        
        # Parse reached times for summary stats
        orig_target_time = parse_target_reached(orig_reached_file)
        work_target_time = parse_target_reached(work_reached_file)
        
        orig_reached_times.append(orig_target_time)
        work_reached_times.append(work_target_time)
        
        # ------------------ Set 1: Up to TTR Limit ------------------
        print(f"Generating TTR-limited plots for {trial}...")
        ttr_comp_path = os.path.join(output_dir, "TTR_comparison.png")
        ttr_bars_path = os.path.join(output_dir, "TTR_bars.png")
        
        generate_cumulative_plot(orig_hit_file, orig_reached_file, work_hit_file, work_reached_file,
                                 use_ttr_limit=True, output_filename=ttr_comp_path, total_blocks=total_blocks, cve=args.cve)
        generate_bar_plot(orig_hit_file, orig_reached_file, work_hit_file, work_reached_file, work_mapping_file,
                          use_ttr_limit=True, output_filename=ttr_bars_path, cve=args.cve)
        
        # Collect limit run data
        orig_times_l, orig_counts_l = parse_blocks_hit_cumulative(orig_hit_file, limit_time=orig_target_time)
        work_times_l, work_counts_l = parse_blocks_hit_cumulative(work_hit_file, limit_time=work_target_time)
        orig_runs_limit.append((orig_times_l, orig_counts_l))
        work_runs_limit.append((work_times_l, work_counts_l))
        
        # Collect limit raw hits data
        orig_ctrl_l, orig_call_l = parse_dgf_log_raw(orig_hit_file, limit_time=orig_target_time)
        work_ctrl_l, work_call_l = parse_dgf_log_raw(work_hit_file, limit_time=work_target_time)
        orig_raw_limit.append((orig_ctrl_l, orig_call_l))
        work_raw_limit.append((work_ctrl_l, work_call_l))
        
        # ------------------ Set 2: Full Run (Furthest) ------------------
        print(f"Generating Full Run (unlimited) plots for {trial}...")
        ttr_comp_full_path = os.path.join(output_dir, "TTR_comparison_full.png")
        ttr_bars_full_path = os.path.join(output_dir, "TTR_bars_full.png")
        
        generate_cumulative_plot(orig_hit_file, orig_reached_file, work_hit_file, work_reached_file,
                                 use_ttr_limit=False, output_filename=ttr_comp_full_path, total_blocks=total_blocks, cve=args.cve)
        generate_bar_plot(orig_hit_file, orig_reached_file, work_hit_file, work_reached_file, work_mapping_file,
                          use_ttr_limit=False, output_filename=ttr_bars_full_path, cve=args.cve)
                          
        # Collect full run data
        orig_times_f, orig_counts_f = parse_blocks_hit_cumulative(orig_hit_file, limit_time=None)
        work_times_f, work_counts_f = parse_blocks_hit_cumulative(work_hit_file, limit_time=None)
        orig_runs_full.append((orig_times_f, orig_counts_f))
        work_runs_full.append((work_times_f, work_counts_f))
        
        # Collect full raw hits data
        orig_ctrl_f, orig_call_f = parse_dgf_log_raw(orig_hit_file, limit_time=None)
        work_ctrl_f, work_call_f = parse_dgf_log_raw(work_hit_file, limit_time=None)
        orig_raw_full.append((orig_ctrl_f, orig_call_f))
        work_raw_full.append((work_ctrl_f, work_call_f))
        
    # Generate overall summary TTR plots
    if orig_runs_limit or work_runs_limit:
        print("\n================ Generating TTR Summary Plots ================")
        ttr_summary_path = os.path.join(plot_base_dir, "TTR_comparison_summary.png")
        generate_cumulative_summary_plot(orig_runs_limit, orig_reached_times, work_runs_limit, work_reached_times,
                                         use_ttr_limit=True, output_filename=ttr_summary_path, total_blocks=total_blocks, cve=args.cve)
                                         
        ttr_summary_full_path = os.path.join(plot_base_dir, "TTR_comparison_full_summary.png")
        generate_cumulative_summary_plot(orig_runs_full, orig_reached_times, work_runs_full, work_reached_times,
                                         use_ttr_limit=False, output_filename=ttr_summary_full_path, total_blocks=total_blocks, cve=args.cve)
                                         
    # Generate overall summary TTR bar plots
    if orig_raw_limit or work_raw_limit:
        print("\n================ Generating TTR Bar Summary Plots ================")
        ttr_bars_summary_path = os.path.join(plot_base_dir, "TTR_bars_summary.png")
        generate_bar_summary_plot(orig_raw_limit, work_raw_limit, work_mapping_file,
                                   use_ttr_limit=True, output_filename=ttr_bars_summary_path, cve=args.cve)
                                   
        ttr_bars_summary_full_path = os.path.join(plot_base_dir, "TTR_bars_full_summary.png")
        generate_bar_summary_plot(orig_raw_full, work_raw_full, work_mapping_file,
                                   use_ttr_limit=False, output_filename=ttr_bars_summary_full_path, cve=args.cve)
if __name__ == '__main__':
    main()

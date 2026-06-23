#!/usr/bin/env python3
import os
import re
import sys
import argparse
import numpy as np
import matplotlib.pyplot as plt

def parse_target_reached(file_path):
    def parse_single(path):
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'r') as f:
                content = f.read()
                match = re.search(r'Elapsed:\s+([\d\.]+)\s+seconds', content)
                if match:
                    return float(match.group(1))
                match_ms = re.search(r'\((\d+)\s*ms\)', content)
                if match_ms:
                    return float(match_ms.group(1)) / 1000.0
        except Exception as e:
            print(f"Error parsing {path}: {e}")
        return None

    t1 = parse_single(file_path)
    
    # Check for slave file
    slave_file = file_path.replace("dgf_target_reached.txt", "dgf_target_reached_slave.txt")
    if os.path.exists(slave_file):
        t2 = parse_single(slave_file)
        if t1 is not None and t2 is not None:
            return min(t1, t2)
        elif t2 is not None:
            return t2
    return t1

def parse_blocks_hit_cumulative(file_path, limit_time=None):
    block_min_times = {}
    
    def process_file(path):
        if not os.path.exists(path):
            return
        try:
            with open(path, 'r') as f:
                f.readline()  # header
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
                    block = (btype, bid)
                    if block not in block_min_times or sec < block_min_times[block]:
                        block_min_times[block] = sec
        except Exception as e:
            print(f"Error parsing {path}: {e}")
            
    process_file(file_path)
    
    # Check for slave file
    slave_file = file_path.replace("dgf_blocks_hit.txt", "dgf_blocks_hit_slave.txt")
    if os.path.exists(slave_file):
        process_file(slave_file)
        
    if not block_min_times:
        return [], []
        
    events = [(sec, block) for block, sec in block_min_times.items()]
    events.sort(key=lambda x: x[0])
    
    times = [0.0]
    counts = [0]
    seen_blocks = set()
    
    for sec, block in events:
        if block not in seen_blocks:
            seen_blocks.add(block)
            times.append(sec)
            counts.append(len(seen_blocks))
            
    if limit_time is not None and (not times or times[-1] < limit_time):
        times.append(limit_time)
        counts.append(counts[-1] if counts else 0)
        
    return times, counts

def parse_dgf_log_raw(filepath, limit_time=None):
    control_hits = {}
    caller_hits = {}
    
    def process_file(path):
        if not os.path.exists(path):
            return
        try:
            with open(path, 'r') as f:
                f.readline()
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
                        if bid not in control_hits or elapsed_ms < control_hits[bid]:
                            control_hits[bid] = elapsed_ms
                    elif btype == 1:
                        if bid not in caller_hits or elapsed_ms < caller_hits[bid]:
                            caller_hits[bid] = elapsed_ms
        except Exception as e:
            print(f"Error parsing raw {path}: {e}")
            
    process_file(filepath)
    
    # Check for slave file
    slave_file = filepath.replace("dgf_blocks_hit.txt", "dgf_blocks_hit_slave.txt")
    if os.path.exists(slave_file):
        process_file(slave_file)
        
    return control_hits, caller_hits

def find_target_id_and_type(block_mapping_path):
    if not os.path.exists(block_mapping_path):
        return None, None
    try:
        with open(block_mapping_path, 'r') as f:
            f.readline()
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

def generate_cumulative_plot(methods, method_dirs, use_ttr_limit, output_filename, total_blocks=None, cve="CVE"):
    reached_times = {}
    run_data = {}
    
    for method, m_dir in zip(methods, method_dirs):
        reached_file = os.path.join(m_dir, "dgf_target_reached.txt")
        hit_file = os.path.join(m_dir, "dgf_blocks_hit.txt")
        
        target_time = parse_target_reached(reached_file) if use_ttr_limit else None
        reached_times[method] = parse_target_reached(reached_file)
        
        times, counts = parse_blocks_hit_cumulative(hit_file, limit_time=target_time)
        run_data[method] = (times, counts)
        
    plt.figure(figsize=(10, 6))
    
    for method in methods:
        times, counts = run_data[method]
        label, color = get_method_info(method)
        plt.step(times, counts, where='post', label=label, color=color, linewidth=2)
        
        actual_reached = reached_times[method]
        if actual_reached:
            plt.axvline(x=actual_reached, color=color, linestyle='--', alpha=0.8,
                        label=f'{label} Reached ({actual_reached:.2f}s)')
            
    text_lines = []
    base_method = methods[0]
    base_reached = reached_times[base_method]
    
    for method in methods:
        times, counts = run_data[method]
        label, _ = get_method_info(method)
        actual_reached = reached_times[method]
        final_blocks = counts[-1] if counts else 0
        
        if total_blocks:
            pct = final_blocks / total_blocks * 100
            text_lines.append(f"{method} Blocks: {final_blocks} ({pct:.1f}%)")
        else:
            text_lines.append(f"{method} Blocks: {final_blocks}")
            
        if method != base_method and base_reached and actual_reached:
            speedup = base_reached / actual_reached
            time_saved = (base_reached - actual_reached) / base_reached * 100
            text_lines.append(f"  Speedup vs {base_method}: {speedup:.2f}x (Saved {time_saved:.1f}%)")
            
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
        max_target_time = max(filter(None, reached_times.values()), default=None)
        if max_target_time:
            plt.xlim(0, max_target_time * 1.05)
    else:
        all_times_list = []
        for method in methods:
            all_times_list.extend(run_data[method][0])
        if all_times_list:
            plt.xlim(0, max(all_times_list) * 1.05)
            
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(loc='best', fontsize=10)
    plt.tight_layout()
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Comparison plot successfully saved as '{output_filename}'")

def parse_block_mapping_ids(block_mapping_path):
    control_ids = []
    caller_ids = []
    if not os.path.exists(block_mapping_path):
        return control_ids, caller_ids
    try:
        with open(block_mapping_path, 'r') as f:
            f.readline()
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

def generate_bar_plot(methods, method_dirs, work_mapping_file, use_ttr_limit, output_filename, cve="CVE"):
    reached_times = {}
    method_ctrl_hits = {}
    method_call_hits = {}
    
    for method, m_dir in zip(methods, method_dirs):
        reached_file = os.path.join(m_dir, "dgf_target_reached.txt")
        hit_file = os.path.join(m_dir, "dgf_blocks_hit.txt")
        
        target_time = parse_target_reached(reached_file) if use_ttr_limit else None
        reached_times[method] = target_time
        
        ctrl, call = parse_dgf_log_raw(hit_file, limit_time=target_time)
        method_ctrl_hits[method] = ctrl
        method_call_hits[method] = call
        
    target_id, target_type = find_target_id_and_type(work_mapping_file)
    if target_id is not None:
        print(f"Target block detected: ID={target_id}, Type={target_type}")
        
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 10))
    num_methods = len(methods)
    width = 0.8 / num_methods
    
    mapped_ctrl, mapped_call = parse_block_mapping_ids(work_mapping_file)
    if mapped_ctrl:
        max_ctrl_val = max(mapped_ctrl)
    else:
        all_ctrl_keys = []
        for ctrl in method_ctrl_hits.values():
            all_ctrl_keys.extend(ctrl.keys())
        max_ctrl_val = max(all_ctrl_keys) if all_ctrl_keys else 145
        
    control_ids = []
    for bid in range(max_ctrl_val + 1):
        if any(bid in ctrl for ctrl in method_ctrl_hits.values()):
            control_ids.append(bid)
            
    def sort_ctrl_key(bid):
        sort_tuple = []
        for i, method in enumerate(methods):
            ctrl = method_ctrl_hits[method]
            if bid in ctrl:
                sort_tuple.append((i, ctrl[bid]))
                break
        else:
            sort_tuple.append((num_methods, 0.0))
        return sort_tuple[0]
        
    control_ids.sort(key=sort_ctrl_key)
    
    x_indices_ctrl = list(range(len(control_ids)))
    
    for idx, method in enumerate(methods):
        ctrl = method_ctrl_hits[method]
        times = [ctrl.get(bid, 0.0) / 1000.0 for bid in control_ids]
        label, color = get_method_info(method)
        offset = (idx - (num_methods - 1) / 2) * width
        ax1.bar([x + offset for x in x_indices_ctrl], times, width, label=label, color=color)
        
    if target_id is not None and target_type == 'Control' and target_id in control_ids:
        target_idx = control_ids.index(target_id)
        ax1.axvline(x=target_idx, color='#d62728', linestyle='--', linewidth=1.8, alpha=0.9, label=f'Target Block (ID {target_id})')
        
    title_suffix = " (Before Target Reached)" if use_ttr_limit else " (Full Run)"
    ax1.set_title(f'Control BBs (Type 0) First Hit Time ({cve})' + title_suffix, fontsize=14, fontweight='bold')
    ax1.set_xlabel('Control Block ID', fontsize=11)
    ax1.set_ylabel('Hit Time (seconds)', fontsize=11)
    ax1.set_xticks(x_indices_ctrl)
    ax1.set_xticklabels([f"{bid}\n(Target)" if (bid == target_id and target_type == 'Control') else str(bid) for bid in control_ids], rotation=45, fontsize=8)
    ax1.grid(True, axis='y', linestyle=':', alpha=0.6)
    ax1.legend(loc='upper right')
    
    if mapped_call:
        max_call_val = max(mapped_call)
    else:
        all_call_keys = []
        for call in method_call_hits.values():
            all_call_keys.extend(call.keys())
        max_call_val = max(all_call_keys) if all_call_keys else 40
        
    caller_ids = []
    for bid in range(max_call_val + 1):
        if any(bid in call for call in method_call_hits.values()):
            caller_ids.append(bid)
            
    def sort_call_key(bid):
        sort_tuple = []
        for i, method in enumerate(methods):
            call = method_call_hits[method]
            if bid in call:
                sort_tuple.append((i, call[bid]))
                break
        else:
            sort_tuple.append((num_methods, 0.0))
        return sort_tuple[0]
        
    caller_ids.sort(key=sort_call_key)
    
    x_indices_call = list(range(len(caller_ids)))
    
    for idx, method in enumerate(methods):
        call = method_call_hits[method]
        times = [call.get(bid, 0.0) / 1000.0 for bid in caller_ids]
        label, color = get_method_info(method)
        offset = (idx - (num_methods - 1) / 2) * width
        ax2.bar([x + offset for x in x_indices_call], times, width, label=label, color=color)
        
    if target_id is not None and target_type == 'Caller' and target_id in caller_ids:
        target_idx = caller_ids.index(target_id)
        ax2.axvline(x=target_idx, color='#d62728', linestyle='--', linewidth=1.8, alpha=0.9, label=f'Target Block (ID {target_id})')
        
    ax2.set_title(f'Caller BBs (Type 1) First Hit Time ({cve})' + title_suffix, fontsize=14, fontweight='bold')
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
    if not times:
        return np.zeros_like(common_times)
    
    t_arr = np.array(times)
    c_arr = np.array(counts)
    
    if t_arr[-1] < common_times[-1]:
        t_arr = np.append(t_arr, common_times[-1])
        c_arr = np.append(c_arr, c_arr[-1])
        
    if t_arr[0] > common_times[0]:
        t_arr = np.insert(t_arr, 0, common_times[0])
        c_arr = np.insert(c_arr, 0, 0)
        
    return np.interp(common_times, t_arr, c_arr)

def geometric_mean(arrays, axis=0):
    with np.errstate(divide='ignore', invalid='ignore'):
        log_data = np.log(arrays)
        mean_log = np.mean(log_data, axis=axis)
        geomean = np.exp(mean_log)
    return np.nan_to_num(geomean, nan=0.0)

def generate_cumulative_summary_plot(methods, method_runs_data, method_reached_times, use_ttr_limit, output_filename, total_blocks=None, cve="CVE"):
    valid_methods = [m for m in methods if method_runs_data.get(m)]
    if not valid_methods:
        print("No runs data available for TTR summary plot.")
        return
        
    all_times = []
    for method in valid_methods:
        for times, _ in method_runs_data[method]:
            if times:
                all_times.extend(times)
                
    if not all_times:
        return
        
    max_time = max(all_times)
    common_times = np.linspace(0, max_time, num=1000)
    
    plt.figure(figsize=(10, 6))
    
    method_means = {}
    
    for idx, method in enumerate(valid_methods):
        label, color = get_method_info(method)
        runs = method_runs_data[method]
        interp_runs = [interpolate_run(r[0], r[1], common_times) for r in runs if r[0]]
        
        if not interp_runs:
            continue
            
        for i, interp in enumerate(interp_runs):
            lbl = f'{label} (individual)' if i == 0 else ""
            plt.plot(common_times, interp, color=color, alpha=0.2, linewidth=1, label=lbl)
            
        mean_curve = geometric_mean(interp_runs, axis=0)
        std_curve = np.std(interp_runs, axis=0)
        method_means[method] = mean_curve[-1]
        
        plt.step(common_times, mean_curve, where='post', color=color, linewidth=2.5, label=f'{label} (average)')
        plt.fill_between(common_times, np.maximum(0, mean_curve - std_curve), mean_curve + std_curve, color=color, alpha=0.1, step='post')
        
        reached_list = [t for t in method_reached_times[method] if t is not None]
        if reached_list:
            geo_mean_reached = geometric_mean_of_list(reached_list)
            plt.axvline(x=geo_mean_reached, color=color, linestyle='--', alpha=0.8,
                        label=f'{label} Reached Geo Mean ({geo_mean_reached:.2f}s)')
            
    text_lines = []
    base_method = valid_methods[0]
    base_reached_list = [t for t in method_reached_times[base_method] if t is not None]
    geo_mean_base = geometric_mean_of_list(base_reached_list) if base_reached_list else None
    
    for method in valid_methods:
        label, _ = get_method_info(method)
        final_avg = method_means.get(method, 0.0)
        
        if total_blocks:
            pct = final_avg / total_blocks * 100
            text_lines.append(f"Avg {method} Blocks: {final_avg:.1f} ({pct:.1f}%)")
        else:
            text_lines.append(f"Avg {method} Blocks: {final_avg:.1f}")
            
        reached_list = [t for t in method_reached_times[method] if t is not None]
        if method != base_method and geo_mean_base and reached_list:
            geo_mean_m = geometric_mean_of_list(reached_list)
            if geo_mean_m > 0:
                speedup = geo_mean_base / geo_mean_m
                time_saved = (geo_mean_base - geo_mean_m) / geo_mean_base * 100
                text_lines.append(f"  Avg Speedup: {speedup:.2f}x (Saved {time_saved:.1f}%)")
                
    if not use_ttr_limit and total_blocks is not None:
        text_lines.append(f"Total Unique Blocks: {total_blocks}")
        
    if text_lines:
        textstr = "\n".join(text_lines)
        props = dict(boxstyle='round', facecolor='#e6f2ff', alpha=0.8, edgecolor='#1f77b4')
        plt.text(1.02, 1.0, textstr, transform=plt.gca().transAxes, fontsize=11,
                  verticalalignment='top', bbox=props, fontweight='bold')
                  
    title_suffix = " (Up to Target Reached)" if use_ttr_limit else " (Full Run)"
    plt.title(f'Time to Reach Target (TTR) and Unique Blocks Hit Comparison ({cve})' + title_suffix, fontsize=14, fontweight='bold', pad=15)
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

def generate_bar_summary_plot(methods, method_runs_raw, work_mapping_file, use_ttr_limit, output_filename, cve="CVE"):
    valid_methods = [m for m in methods if method_runs_raw.get(m)]
    if not valid_methods:
        print("No runs raw data available for TTR bar summary plot.")
        return
        
    mapped_ctrl, mapped_call = parse_block_mapping_ids(work_mapping_file)
    
    if mapped_ctrl:
        max_ctrl_val = max(mapped_ctrl)
    else:
        all_ctrl_keys = []
        for method in valid_methods:
            for run in method_runs_raw[method]:
                all_ctrl_keys.extend(run[0].keys())
        max_ctrl_val = max(all_ctrl_keys) if all_ctrl_keys else 145
        
    control_ids = []
    for bid in range(max_ctrl_val + 1):
        if any(bid in run[0] for method in valid_methods for run in method_runs_raw[method]):
            control_ids.append(bid)
            
    def sort_ctrl_key(bid):
        sort_tuple = []
        for idx, method in enumerate(valid_methods):
            runs = method_runs_raw[method]
            hit_times = [run[0][bid] / 1000.0 for run in runs if bid in run[0]]
            if hit_times:
                sort_tuple.append((idx, geometric_mean_of_list(hit_times)))
                break
        else:
            sort_tuple.append((len(valid_methods), 0.0))
        return sort_tuple[0]
        
    control_ids.sort(key=sort_ctrl_key)
    
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 10))
    num_methods = len(valid_methods)
    width = 0.8 / num_methods
    
    x_indices_ctrl = list(range(len(control_ids)))
    
    for idx, method in enumerate(valid_methods):
        label, color = get_method_info(method)
        runs = method_runs_raw[method]
        times = []
        for bid in control_ids:
            hit_times = [run[0][bid] / 1000.0 for run in runs if bid in run[0]]
            times.append(geometric_mean_of_list(hit_times))
        offset = (idx - (num_methods - 1) / 2) * width
        ax1.bar([x + offset for x in x_indices_ctrl], times, width, label=f'{label} (Geo Mean)', color=color)
        
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
    
    if mapped_call:
        max_call_val = max(mapped_call)
    else:
        all_call_keys = []
        for method in valid_methods:
            for run in method_runs_raw[method]:
                all_call_keys.extend(run[1].keys())
        max_call_val = max(all_call_keys) if all_call_keys else 40
        
    caller_ids = []
    for bid in range(max_call_val + 1):
        if any(bid in run[1] for method in valid_methods for run in method_runs_raw[method]):
            caller_ids.append(bid)
            
    def sort_call_key(bid):
        sort_tuple = []
        for idx, method in enumerate(valid_methods):
            runs = method_runs_raw[method]
            hit_times = [run[1][bid] / 1000.0 for run in runs if bid in run[1]]
            if hit_times:
                sort_tuple.append((idx, geometric_mean_of_list(hit_times)))
                break
        else:
            sort_tuple.append((len(valid_methods), 0.0))
        return sort_tuple[0]
        
    caller_ids.sort(key=sort_call_key)
    
    x_indices_call = list(range(len(caller_ids)))
    
    for idx, method in enumerate(valid_methods):
        label, color = get_method_info(method)
        runs = method_runs_raw[method]
        times = []
        for bid in caller_ids:
            hit_times = [run[1][bid] / 1000.0 for run in runs if bid in run[1]]
            times.append(geometric_mean_of_list(hit_times))
        offset = (idx - (num_methods - 1) / 2) * width
        ax2.bar([x + offset for x in x_indices_call], times, width, label=f'{label} (Geo Mean)', color=color)
        
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
    parser.add_argument("--cve", type=str, default="CVE", help="CVE identifier")
    parser.add_argument("--trial-name", type=str, help="Specific trial run name to check. If not specified, the latest one will be used.")
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
            print(f"Error: No trial runs found under {root}. Exiting.")
            sys.exit(1)
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
    valid_methods = [m for m in methods if os.path.exists(os.path.join(first_session_path, m))]
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
            
    total_blocks = None
    work_mapping_file = None
    for method in valid_methods:
        for item in trial_items:
            compile_info_path = os.path.join(root, item["session_dir"], method, item["trial"], "dgf_compile_info.txt")
            total_blocks = parse_total_unique_blocks(compile_info_path)
            if total_blocks:
                break
        if total_blocks:
            break
            
    for method in valid_methods:
        for item in trial_items:
            mapping_path = os.path.join(root, item["session_dir"], method, item["trial"], "dgf_block_mapping.txt")
            if os.path.exists(mapping_path):
                work_mapping_file = mapping_path
                break
        if work_mapping_file:
            break
        
    if total_blocks:
        print(f"Parsed total unique blocks: {total_blocks}")
    if work_mapping_file:
        print(f"Using block mapping file: {work_mapping_file}")
        
    method_runs_limit = {m: [] for m in valid_methods}
    method_runs_full = {m: [] for m in valid_methods}
    method_reached_times = {m: [] for m in valid_methods}
    method_runs_raw_limit = {m: [] for m in valid_methods}
    method_runs_raw_full = {m: [] for m in valid_methods}
    
    for item in trial_items:
        print(f"\n================ Processing {item['label']} ================")
        output_dir = os.path.join(plot_base_dir, item["session_dir"], item["trial"])
        os.makedirs(output_dir, exist_ok=True)
        trial_method_dirs = [os.path.join(root, item["session_dir"], m, item["trial"]) for m in valid_methods]
        
        print(f"Generating TTR-limited plots for {item['label']}...")
        ttr_comp_path = os.path.join(output_dir, "TTR_comparison.png")
        ttr_bars_path = os.path.join(output_dir, "TTR_bars.png")
        
        generate_cumulative_plot(valid_methods, trial_method_dirs, use_ttr_limit=True, output_filename=ttr_comp_path, total_blocks=total_blocks, cve=args.cve)
        if work_mapping_file:
            generate_bar_plot(valid_methods, trial_method_dirs, work_mapping_file, use_ttr_limit=True, output_filename=ttr_bars_path, cve=args.cve)
            
        for method, m_dir in zip(valid_methods, trial_method_dirs):
            reached_file = os.path.join(m_dir, "dgf_target_reached.txt")
            hit_file = os.path.join(m_dir, "dgf_blocks_hit.txt")
            
            target_time = parse_target_reached(reached_file)
            method_reached_times[method].append(target_time)
            
            times_l, counts_l = parse_blocks_hit_cumulative(hit_file, limit_time=target_time)
            method_runs_limit[method].append((times_l, counts_l))
            
            ctrl_l, call_l = parse_dgf_log_raw(hit_file, limit_time=target_time)
            method_runs_raw_limit[method].append((ctrl_l, call_l))
            
        print(f"Generating Full Run (unlimited) plots for {item['label']}...")
        ttr_comp_full_path = os.path.join(output_dir, "TTR_comparison_full.png")
        ttr_bars_full_path = os.path.join(output_dir, "TTR_bars_full.png")
        
        generate_cumulative_plot(valid_methods, trial_method_dirs, use_ttr_limit=False, output_filename=ttr_comp_full_path, total_blocks=total_blocks, cve=args.cve)
        if work_mapping_file:
            generate_bar_plot(valid_methods, trial_method_dirs, work_mapping_file, use_ttr_limit=False, output_filename=ttr_bars_full_path, cve=args.cve)
            
        for method, m_dir in zip(valid_methods, trial_method_dirs):
            hit_file = os.path.join(m_dir, "dgf_blocks_hit.txt")
            
            times_f, counts_f = parse_blocks_hit_cumulative(hit_file, limit_time=None)
            method_runs_full[method].append((times_f, counts_f))
            
            ctrl_f, call_f = parse_dgf_log_raw(hit_file, limit_time=None)
            method_runs_raw_full[method].append((ctrl_f, call_f))
            
    print("\n================ Generating TTR Summary Plots ================")
    if trial_name == "all":
        ttr_summary_path = os.path.join(plot_base_dir, "TTR_comparison_summary.png")
        ttr_summary_full_path = os.path.join(plot_base_dir, "TTR_comparison_full_summary.png")
    else:
        ttr_summary_path = os.path.join(plot_base_dir, f"{trial_name}_TTR_comparison_summary.png")
        ttr_summary_full_path = os.path.join(plot_base_dir, f"{trial_name}_TTR_comparison_full_summary.png")
        
    generate_cumulative_summary_plot(valid_methods, method_runs_limit, method_reached_times, use_ttr_limit=True, output_filename=ttr_summary_path, total_blocks=total_blocks, cve=args.cve)
    generate_cumulative_summary_plot(valid_methods, method_runs_full, method_reached_times, use_ttr_limit=False, output_filename=ttr_summary_full_path, total_blocks=total_blocks, cve=args.cve)
    
    if work_mapping_file:
        print("\n================ Generating TTR Bar Summary Plots ================")
        if trial_name == "all":
            ttr_bars_summary_path = os.path.join(plot_base_dir, "TTR_bars_summary.png")
            ttr_bars_summary_full_path = os.path.join(plot_base_dir, "TTR_bars_full_summary.png")
        else:
            ttr_bars_summary_path = os.path.join(plot_base_dir, f"{trial_name}_TTR_bars_summary.png")
            ttr_bars_summary_full_path = os.path.join(plot_base_dir, f"{trial_name}_TTR_bars_full_summary.png")
            
        generate_bar_summary_plot(valid_methods, method_runs_raw_limit, work_mapping_file, use_ttr_limit=True, output_filename=ttr_bars_summary_path, cve=args.cve)
        generate_bar_summary_plot(valid_methods, method_runs_raw_full, work_mapping_file, use_ttr_limit=False, output_filename=ttr_bars_summary_full_path, cve=args.cve)

if __name__ == '__main__':
    main()

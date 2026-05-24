import os
import re
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

def generate_cumulative_plot(orig_hit_file, orig_reached_file, work_hit_file, work_reached_file, use_ttr_limit, output_filename):
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
        
    title_suffix = " (Up to Target Reached)" if use_ttr_limit else " (Full Run)"
    plt.title('Time to Reach Target (TTR) and Unique Blocks Hit Comparison' + title_suffix, fontsize=14, fontweight='bold', pad=15)
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
    plt.savefig(output_filename, dpi=300)
    plt.close()
    print(f"Comparison plot successfully saved as '{output_filename}'")

def generate_bar_plot(orig_hit_file, orig_reached_file, work_hit_file, work_reached_file, work_mapping_file, use_ttr_limit, output_filename):
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
    control_ids = [i for i in range(146) if i in orig_ctrl or i in work_ctrl]
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
    ax1.set_title('Control BBs (Type 0) First Hit Time (Sorted by Blue\'s Hit Time)' + title_suffix, fontsize=14, fontweight='bold')
    ax1.set_xlabel('Control Block ID', fontsize=11)
    ax1.set_ylabel('Hit Time (seconds)', fontsize=11)
    ax1.set_xticks(x_indices_ctrl)
    ax1.set_xticklabels([f"{bid}\n(Target)" if (bid == target_id and target_type == 'Control') else str(bid) for bid in control_ids], rotation=45, fontsize=8)
    ax1.grid(True, axis='y', linestyle=':', alpha=0.6)
    ax1.legend(loc='upper right')
    
    # Filter Caller BBs (Type 1) to only include those hit by at least one group
    caller_ids = [i for i in range(41) if i in orig_call or i in work_call]
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
    
    ax2.set_title('Caller BBs (Type 1) First Hit Time (Sorted by Blue\'s Hit Time)' + title_suffix, fontsize=14, fontweight='bold')
    ax2.set_xlabel('Caller Block ID', fontsize=11)
    ax2.set_ylabel('Hit Time (seconds)', fontsize=11)
    ax2.set_xticks(x_indices_call)
    ax2.set_xticklabels([f"{bid}\n(Target)" if (bid == target_id and target_type == 'Caller') else str(bid) for bid in caller_ids], rotation=45, fontsize=8)
    ax2.grid(True, axis='y', linestyle=':', alpha=0.6)
    ax2.legend(loc='upper right')
    
    plt.tight_layout()
    plt.savefig(output_filename, dpi=300)
    plt.close()
    print(f"Bar comparison plot successfully saved as '{output_filename}'")

def main():
    # Define paths
    orig_dir = "bench/ICD/swftophp-4.8-original/artifact"
    work_dir = "bench/ICD/swftophp-4.8/artifact"
    
    orig_hit_file = os.path.join(orig_dir, "dgf_blocks_hit.txt")
    orig_reached_file = os.path.join(orig_dir, "dgf_target_reached.txt")
    
    work_hit_file = os.path.join(work_dir, "dgf_blocks_hit.txt")
    work_reached_file = os.path.join(work_dir, "dgf_target_reached.txt")
    work_mapping_file = os.path.join(work_dir, "dgf_block_mapping.txt")
    
    # ------------------ Set 1: Up to TTR Limit ------------------
    print("Generating TTR-limited plots...")
    generate_cumulative_plot(orig_hit_file, orig_reached_file, work_hit_file, work_reached_file,
                             use_ttr_limit=True, output_filename="TTR_comparison.png")
    generate_bar_plot(orig_hit_file, orig_reached_file, work_hit_file, work_reached_file, work_mapping_file,
                      use_ttr_limit=True, output_filename="TTR_bars.png")
    
    # ------------------ Set 2: Full Run (Furthest) ------------------
    print("Generating Full Run (unlimited) plots...")
    generate_cumulative_plot(orig_hit_file, orig_reached_file, work_hit_file, work_reached_file,
                             use_ttr_limit=False, output_filename="TTR_comparison_full.png")
    generate_bar_plot(orig_hit_file, orig_reached_file, work_hit_file, work_reached_file, work_mapping_file,
                      use_ttr_limit=False, output_filename="TTR_bars_full.png")

if __name__ == '__main__':
    main()

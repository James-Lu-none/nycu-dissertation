#!/usr/bin/env python3
import os
import re
import subprocess
import argparse

def parse_trace(trace_path):
    """
    Parses the target stack trace from the host.
    Supports lines prefixed with line numbers (e.g., "1: decompile.c:425") or just file:line.
    """
    trace = []
    if not os.path.exists(trace_path):
        print(f"Error: Trace file {trace_path} not found.")
        return trace
    with open(trace_path, 'r') as f:
        for line in f:
            line = line.strip()
            line = re.sub(r'^\d+:\s*', '', line)
            if line:
                trace.append(line)
    return trace

def check_crash_in_container(container_name, crash_filename, target_trace, binary_in_container):
    """
    Runs the crash inside the specified docker container using gdb, and checks if
    the backtrace matches the target trace.
    """
    crash_path_in_container = f"/workspace/out/main/crashes/{crash_filename}"
    
    # Construct the docker exec command
    # We run gdb inside the container to get the backtrace
    cmd = [
        "docker", "exec", container_name,
        "gdb", "--batch", "-q",
        "-ex", f"r {crash_path_in_container}",
        "-ex", "bt",
        binary_in_container
    ]
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        bt_text = result.stdout
    except Exception as e:
        print(f"  [!] Error running docker exec for container {container_name}: {e}")
        return False
        
    # Extract file:line frames from backtrace
    frames = []
    for line in bt_text.splitlines():
        match = re.search(r'([\w\-]+\.[c|h]):(\d+)', line)
        if match:
            frames.append(f"{match.group(1)}:{match.group(2)}")
            
    if not frames:
        return False
        
    # Compare the top frames with the target trace
    # Usually matching the top min(len(frames), len(target_trace), 4) frames is extremely specific and robust
    match_len = min(len(frames), len(target_trace), 4)
    if match_len == 0:
        return False
        
    for i in range(match_len):
        if frames[i] != target_trace[i]:
            return False
            
    return True

def main():
    parser = argparse.ArgumentParser(description="Calculate true Time to Exposure (TTE) by checking crash backtraces.")
    parser.add_argument("--root", required=True, help="Root directory of the CVE artifact data (e.g. ./artifact/CVE-2018-20427)")
    parser.add_argument("--methods", nargs="+", required=True, help="Fuzzer methods to compare (e.g. swftophp-afl-origin swftophp-afl-icd)")
    parser.add_argument("--cve", required=True, help="CVE identifier (e.g. CVE-2018-20427)")
    parser.add_argument("--trace", required=True, help="Path to the target stack trace file")
    parser.add_argument("--binary", default="/workspace/swftophp", help="Binary path inside the docker containers")
    parser.add_argument("--update-reached", action="store_true", help="Overwrite local dgf_target_reached.txt with true TTE")
    args = parser.parse_args()

    root = os.path.expanduser(args.root)
    target_trace = parse_trace(args.trace)
    
    if not target_trace:
        print("Error: Could not parse target trace. Exiting.")
        return
        
    detected = set()
    for method in args.methods:
        method_dir = os.path.join(root, method)
        if os.path.exists(method_dir):
            for name in os.listdir(method_dir):
                match = re.match(r'^trial(\w+)$', name)
                if match:
                    detected.add(match.group(1))
    def sort_key(x):
        digits = re.search(r'\d+', x)
        return (0, int(digits.group())) if digits else (1, x)
    trials = sorted(list(detected), key=sort_key)
    if not trials:
        print("Error: No trial folders (e.g. trial1) found automatically. Exiting.")
        return
    print(f"Automatically detected trials: {trials}")
        
    print(f"Target stack trace to match: {target_trace}")
    print(f"Analyzing methods: {args.methods} on trials {trials}")
    
    for method in args.methods:
        print(f"\n================ Method: {method} ================")
        for trial in trials:
            trial_folder = f"trial{trial}"
            container_name = f"{method}-{trial}"
            
            local_trial_dir = os.path.join(root, method, trial_folder)
            local_crashes_dir = os.path.join(local_trial_dir, "out/main/crashes")
            
            if not os.path.exists(local_crashes_dir):
                print(f"Trial {trial}: Crashes directory not found locally at {local_crashes_dir}. Skipping.")
                continue
                
            # List local crash files to get filenames
            crash_files = [f for f in os.listdir(local_crashes_dir) if f.startswith("id:")]
            
            # Sort crashes by their 'time' parameter in the filename to check the earliest first
            def get_crash_time(filename):
                time_match = re.search(r'time:(\d+)', filename)
                return int(time_match.group(1)) if time_match else float('inf')
                
            crash_files.sort(key=get_crash_time)
            
            print(f"Trial {trial}: Found {len(crash_files)} crash files. Triaging to find TTE...")
            
            tte_ms = None
            matching_crash = None
            
            for crash_file in crash_files:
                elapsed_ms = get_crash_time(crash_file)
                
                # Check if this crash triggers the target CVE trace
                is_match = check_crash_in_container(
                    container_name=container_name,
                    crash_filename=crash_file,
                    target_trace=target_trace,
                    binary_in_container=args.binary
                )
                
                if is_match:
                    tte_ms = elapsed_ms
                    matching_crash = crash_file
                    break  # Found the first one! Since they are sorted, this is the true TTE
            
            if tte_ms is not None:
                tte_sec = tte_ms / 1000.0
                print(f"  [+] True TTE: {tte_sec:.3f} seconds ({tte_ms} ms) | Crash: {matching_crash}")
                
                if args.update_reached:
                    reached_file_path = os.path.join(local_trial_dir, "dgf_target_reached.txt")
                    with open(reached_file_path, "w") as rf:
                        rf.write("Target reached!\n")
                        rf.write(f"Elapsed:    {tte_sec:.3f} seconds ({tte_ms} ms)\n")
                        rf.write(f"Crash File: {matching_crash}\n")
                    print(f"  [+] Updated local {reached_file_path}")
            else:
                print("  [-] No crashes matched the target stack trace for this trial.")

if __name__ == '__main__':
    main()

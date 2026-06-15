import os
import re
import subprocess
import sys

USE_11729_TRIAGE = False

def get_crash_time(filename):
    time_match = re.search(r'time:(\d+)', filename)
    return int(time_match.group(1)) if time_match else float('inf')

def is_frame_match(f1, f2, line_tolerance=5):
    if f1 == f2:
        return True
    try:
        file1, line1 = f1.split(':')
        file2, line2 = f2.split(':')
        if file1 == file2 and abs(int(line1) - int(line2)) <= line_tolerance:
            return True
    except Exception:
        pass
    return False

def get_crash_func_caller(buf, idx=1):
    rstr = r"#" + str(idx) + r"\s+0x[0-9a-f]+ in ([\w\d_]+)"
    match = re.search(rstr, buf)
    if match:
        return match.group(1)
    rstr_orig = "#" + str(idx) + r" 0x[0-9a-f]+ in [\S]+"
    match_orig = re.search(rstr_orig, buf)
    if match_orig is None:
        return ""
    start_idx, end_idx = match_orig.span()
    line = buf[start_idx:end_idx]
    return line.split()[-1]

def check_swftophp_2017_11729(buf):
    if "heap-buffer-overflow" in buf:
        if "decompile.c:868" in buf:
            if get_crash_func_caller(buf) == "decompileINCR_DECR":
                return True
    return False

def main():
    binary = sys.argv[1]
    flags = sys.argv[2:]
    
    trace_path = "/workspace/out/main/crashes/.target_trace"
    if not os.path.exists(trace_path):
        print("Error: .target_trace not found in container")
        sys.exit(1)
        
    target_trace = []
    with open(trace_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                target_trace.append(line)
                
    if not target_trace:
        print("Error: target_trace is empty")
        sys.exit(1)
        
    crashes_dir = "/workspace/out/main/crashes"
    crash_files = [f for f in os.listdir(crashes_dir) if f.startswith("id:")]
    crash_files.sort(key=get_crash_time)
    
    match_required = min(len(target_trace), 4)
    required_target_trace = target_trace[:match_required]
    
    tte_ms = None
    matching_crash = None
    
    for crash_file in crash_files:
        elapsed_ms = get_crash_time(crash_file)
        crash_path = os.path.join(crashes_dir, crash_file)
        
        if "@@" in flags:
            run_args = [crash_path if arg == "@@" else arg for arg in flags]
            cmd = [
                "gdb", "-iex", "set python ignore-environment on",
                "--batch", "-q",
                "-ex", "run",
                "-ex", "bt",
                "--args", binary
            ] + run_args
        else:
            cmd = [
                "gdb", "-iex", "set python ignore-environment on",
                "--batch", "-q",
                "-ex", f"run < {crash_path}",
                "-ex", "bt",
                binary
            ]
        
        try:
            env = os.environ.copy()
            env.pop("PYTHONHOME", None)
            env.pop("PYTHONPATH", None)
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4, env=env)
            bt_text = res.stdout.decode('utf-8', errors='replace')
            full_log = bt_text + "\n" + res.stderr.decode('utf-8', errors='replace')
        except Exception:
            continue
            
        found_match = False
        if USE_11729_TRIAGE:
            if check_swftophp_2017_11729(full_log):
                print(f"DEBUG: {crash_file} matched CVE-2017-11729 logic")
                found_match = True
        else:
            frames = []
            for line in bt_text.splitlines():
                m = re.search(r'([\w\-]+\.[c|h]):(\d+)', line)
                if m:
                    frames.append(f"{m.group(1)}:{m.group(2)}")
                    
            start_indices = [idx for idx, f in enumerate(frames) if is_frame_match(f, required_target_trace[0])]
            
            if start_indices:
                print(f"DEBUG: {crash_file} matched required_target_trace[0] ({required_target_trace[0]}) at frame indices {start_indices}")
                print(f"DEBUG: Full backtrace frames for {crash_file}: {frames}")
                
            for start_idx in start_indices:
                matched_count = 1
                curr_idx = start_idx + 1
                matched_subset = [frames[start_idx]]
                for target in required_target_trace[1:]:
                    for j in range(curr_idx, len(frames)):
                        if is_frame_match(frames[j], target):
                            matched_count += 1
                            curr_idx = j + 1
                            matched_subset.append(frames[j])
                            break
                if matched_count >= match_required:
                    print(f"DEBUG: {crash_file} matched target trace subsequence (matched {matched_count} frames: {matched_subset})")
                    found_match = True
                    break
                else:
                    print(f"DEBUG: {crash_file} matched only {matched_count} frames: {matched_subset} (required {match_required})")
                
        if found_match:
            tte_ms = elapsed_ms
            matching_crash = crash_file
            break
            
    result_path = "/workspace/out/main/crashes/.triage_result"
    with open(result_path, 'w') as f:
        if tte_ms is not None:
            f.write(f"FOUND\n{tte_ms}\n{matching_crash}\n")
        else:
            f.write("NOT_FOUND\n")

if __name__ == '__main__':
    main()

import os
import re
import subprocess
import sys
from triage import *

CVE_NAME = "PLACEHOLDER_CVE_NAME"

def get_triage_function_name(cve):
    if not cve:
        return None
    match = re.search(r'(20\d{2})[-_](\d{4,5})', cve)
    if not match:
        return None
    year, bug_id = match.group(1), match.group(2)
    for prog in ["cxxfilt", "swftophp", "nm", "readelf", "xmllint", "cjpeg", "lrzip", "objdump", "objcopy", "strip"]:
        if prog in cve.lower():
            return f"check_{prog}_{year}_{bug_id}"
    return None

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
    triage_times = []
    
    for crash_file in crash_files:
        elapsed_ms = get_crash_time(crash_file)
        crash_path = os.path.join(crashes_dir, crash_file)
        
        try:
            env = os.environ.copy()
            env.pop("PYTHONHOME", None)
            env.pop("PYTHONPATH", None)
            env["ASAN_OPTIONS"] = "allocator_may_return_null=1,detect_leaks=0"
            
            import time
            t_start = time.time()
            if "@@" in flags:
                run_args = [crash_path if arg == "@@" else arg for arg in flags]
                cmd = [binary] + run_args
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4, env=env)
            else:
                cmd = [binary]
                with open(crash_path, 'rb') as stdin_file:
                    res = subprocess.run(cmd, stdin=stdin_file, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4, env=env)
            t_end = time.time()
            triage_times.append(t_end - t_start)
            
            bt_text = res.stdout.decode('utf-8', errors='replace')
            full_log = bt_text + "\n" + res.stderr.decode('utf-8', errors='replace')
            
            if "AddressSanitizer" not in full_log and "Sanitizer" not in full_log:
                result_path = "/workspace/out/main/crashes/.triage_result"
                with open(result_path, 'w') as f:
                    f.write(f"ERROR\nCrash case '{crash_file}' did not trigger AddressSanitizer!\nProcess execution output:\n{full_log}\n")
                sys.exit(1)
                
        except Exception as e:
            # If sys.exit was called inside try, let it propagate
            if isinstance(e, SystemExit):
                raise e
            continue
            
        found_match = False
        func_name = get_triage_function_name(CVE_NAME)
        if func_name and func_name in globals():
            triage_func = globals()[func_name]
            if triage_func(full_log):
                print(f"DEBUG: {crash_file} matched {func_name} logic")
                found_match = True
        else:
            print(f"DEBUG: No triage method found for {CVE_NAME} (searched: {func_name})")
            # Trace Subsequence matching commented out:
            # frames = []
            # for line in bt_text.splitlines():
            #     m = re.search(r'([\w\-]+\.[c|h]):(\d+)', line)
            #     if m:
            #         frames.append(f"{m.group(1)}:{m.group(2)}")
            #         
            # start_indices = [idx for idx, f in enumerate(frames) if is_frame_match(f, required_target_trace[0])]
            # 
            # if start_indices:
            #     print(f"DEBUG: {crash_file} matched required_target_trace[0] ({required_target_trace[0]}) at frame indices {start_indices}")
            #     print(f"DEBUG: Full backtrace frames for {crash_file}: {frames}")
            #     
            # for start_idx in start_indices:
            #     matched_count = 1
            #     curr_idx = start_idx + 1
            #     matched_subset = [frames[start_idx]]
            #     for target in required_target_trace[1:]:
            #         for j in range(curr_idx, len(frames)):
            #             if is_frame_match(frames[j], target):
            #                 matched_count += 1
            #                 curr_idx = j + 1
            #                 matched_subset.append(frames[j])
            #                 break
            #     if matched_count >= match_required:
            #         print(f"DEBUG: {crash_file} matched target trace subsequence (matched {matched_count} frames: {matched_subset})")
            #         found_match = True
            #         break
            #     else:
            #         print(f"DEBUG: {crash_file} matched only {matched_count} frames: {matched_subset} (required {match_required})")
                
        if found_match:
            # Write full log for the matched crash case to crashes/full_logs/
            logs_dir = "/workspace/out/main/crashes/full_logs"
            os.makedirs(logs_dir, exist_ok=True)
            try:
                os.chmod(logs_dir, 0o777)
            except Exception:
                pass
            log_file_path = os.path.join(logs_dir, f"{crash_file}.log")
            try:
                with open(log_file_path, 'w') as lf:
                    lf.write(full_log)
                os.chmod(log_file_path, 0o666)
            except Exception:
                pass

            tte_ms = elapsed_ms
            matching_crash = crash_file
            break
            
    avg_time = sum(triage_times) / len(triage_times) if triage_times else 0.0
    max_time = max(triage_times) if triage_times else 0.0
    count = len(triage_times)
    
    result_path = "/workspace/out/main/crashes/.triage_result"
    with open(result_path, 'w') as f:
        if tte_ms is not None:
            f.write(f"FOUND\n{tte_ms}\n{matching_crash}\n")
        else:
            f.write("NOT_FOUND\n")
        f.write(f"STATS:{count},{avg_time:.6f},{max_time:.6f}\n")

if __name__ == '__main__':
    main()

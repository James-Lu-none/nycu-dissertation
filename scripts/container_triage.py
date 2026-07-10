import os
import re
import subprocess
import sys
import multiprocessing
import concurrent.futures
import time
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
    
    # Copy binary to /tmp to avoid NFS/Lustre latency during symbolization
    import shutil
    tmp_binary = os.path.join("/tmp", os.path.basename(binary))
    try:
        shutil.copy(binary, tmp_binary)
        os.chmod(tmp_binary, 0o755)
        binary = tmp_binary
    except Exception as e:
        print(f"DEBUG: Failed to copy binary to /tmp: {e}")
    
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
    
    def process_crash(crash_file):
        elapsed_ms = get_crash_time(crash_file)
        crash_path = os.path.join(crashes_dir, crash_file)
        
        env = os.environ.copy()
        env.pop("PYTHONHOME", None)
        env.pop("PYTHONPATH", None)
        for k in list(env.keys()):
            if k.startswith("AFL_") or k.startswith("__AFL_"):
                env.pop(k, None)
        env["ASAN_OPTIONS"] = "allocator_may_return_null=1,detect_leaks=0,symbolize=1"
        env["ASAN_SYMBOLIZER_PATH"] = "/usr/lib/llvm-20/bin/llvm-symbolizer"
        
        t_start = time.time()
        try:
            if "@@" in flags:
                run_args = [crash_path if arg == "@@" else arg for arg in flags]
                cmd = [binary] + run_args
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4, env=env)
            else:
                cmd = [binary] + flags
                with open(crash_path, 'rb') as stdin_file:
                    res = subprocess.run(cmd, stdin=stdin_file, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4, env=env)
            t_end = time.time()
            exec_time = t_end - t_start
            
            bt_text = res.stdout.decode('utf-8', errors='replace')
            full_log = bt_text + "\n" + res.stderr.decode('utf-8', errors='replace')
            
            if "AddressSanitizer" not in full_log and "Sanitizer" not in full_log:
                return {"error": f"Crash case '{crash_file}' did not trigger AddressSanitizer!\nProcess execution output:\n{full_log}", "crash_file": crash_file}
                
        except subprocess.TimeoutExpired:
            print(f"DEBUG: {crash_file} execution timed out")
            return {"timeout": True, "exec_time": 4.0, "crash_file": crash_file}
        except Exception as e:
            if isinstance(e, SystemExit):
                raise e
            import traceback
            err_trace = traceback.format_exc()
            return {"error": f"Exception occurred during triage of '{crash_file}': {str(e)}\nTraceback:\n{err_trace}", "crash_file": crash_file}
            
        found_match = False
        func_name = get_triage_function_name(CVE_NAME)
        if func_name and func_name in globals():
            triage_func = globals()[func_name]
            if triage_func(full_log):
                print(f"DEBUG: {crash_file} matched {func_name} logic")
                found_match = True
        else:
            print(f"DEBUG: No triage method found for {CVE_NAME} (searched: {func_name})")
            
        return {"match": found_match, "elapsed_ms": elapsed_ms, "exec_time": exec_time, "crash_file": crash_file, "full_log": full_log}

    max_workers = min(16, max(1, multiprocessing.cpu_count()))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_crash, cf) for cf in crash_files]
        for future in futures:
            result = future.result()
            
            if "error" in result:
                result_path = "/workspace/out/main/crashes/.triage_result"
                with open(result_path, 'w') as f:
                    f.write(f"ERROR\n{result['error']}\n")
                # Cancel remaining
                for f2 in futures:
                    f2.cancel()
                sys.exit(1)
                
            if "timeout" in result:
                triage_times.append(result["exec_time"])
                continue
                
            triage_times.append(result["exec_time"])
            if result.get("match"):
                tte_ms = result["elapsed_ms"]
                matching_crash = result["crash_file"]
                full_log = result["full_log"]
                
                # Write full log for the matched crash case to crashes/full_logs/
                logs_dir = "/workspace/out/main/crashes/full_logs"
                os.makedirs(logs_dir, exist_ok=True)
                try:
                    os.chmod(logs_dir, 0o777)
                except Exception:
                    pass
                log_file_path = os.path.join(logs_dir, f"{matching_crash}.log")
                try:
                    with open(log_file_path, 'w') as lf:
                        lf.write(full_log)
                    os.chmod(log_file_path, 0o666)
                except Exception:
                    pass
                
                # Cancel remaining
                for f2 in futures:
                    f2.cancel()
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

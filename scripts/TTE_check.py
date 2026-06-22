#!/usr/bin/env python3
import os
import re
import sys
import subprocess
import argparse
import shutil

def parse_trace(trace_path):
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

def parse_fuzzer_command(benchmark_dir):
    env_path = os.path.join(benchmark_dir, ".env")
    if not os.path.exists(env_path):
        return None
    
    env_vars = {}
    with open(env_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                k, v = line.split('=', 1)
                env_vars[k.strip()] = v.strip().strip('"').strip("'")
                
    target_bin = env_vars.get("TARGET_BIN_BASE")
    if not target_bin:
        target_bin = env_vars.get("TARGET_BIN")
    target_args = env_vars.get("TARGET_ARGS", "")
    
    if target_bin:
        return f"{target_bin} {target_args}".strip()
    return None

def get_docker_image_name(benchmark_dir, method):
    env_path = os.path.join(benchmark_dir, ".env")
    if not os.path.exists(env_path):
        return None
    
    with open(env_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                k, v = line.split('=', 1)
                if k.strip() == "IMAGE_NAME":
                    return v.strip().strip('"').strip("'")
    return None

def check_image_exists(image_name):
    try:
        res = subprocess.run(["docker", "image", "inspect", image_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def triage_crashes_in_container(image_name, binary, flags, local_crashes_dir, target_trace, dest_logs_dir=None):
    local_crashes_dir = os.path.abspath(local_crashes_dir)
    
    trace_path = os.path.join(local_crashes_dir, ".target_trace")
    with open(trace_path, 'w') as f:
        for t in target_trace:
            f.write(t + "\n")
            
    triage_helper_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "container_triage.py")
    if not os.path.exists(triage_helper_path):
        print(f"Error: container_triage.py helper script not found at {triage_helper_path}")
        sys.exit(1)
        
    with open(triage_helper_path, 'r') as f:
        triage_script_content = f.read()

    triage_script_content = triage_script_content.replace("PLACEHOLDER_CVE_NAME", "CVE")

    # Copy triage.py library to local_crashes_dir so the container can import it
    triage_lib_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "triage.py")
    dest_triage_lib = os.path.join(local_crashes_dir, "triage.py")
    shutil.copy(triage_lib_path, dest_triage_lib)

    triage_script_path = os.path.join(local_crashes_dir, ".triage.py")
    with open(triage_script_path, 'w') as f:
        f.write(triage_script_content)
        
    result_path = os.path.join(local_crashes_dir, ".triage_result")
    if os.path.exists(result_path):
        os.remove(result_path)
        
    cmd = [
        "docker", "run", "--rm",
        "--cap-add=SYS_PTRACE",
        "--security-opt", "seccomp=unconfined",
        "-w", "/workspace",
        "-v", f"{local_crashes_dir}:/workspace/out/main/crashes",
        image_name,
        "python3", "/workspace/out/main/crashes/.triage.py",
        binary
    ] + flags
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout_text = result.stdout.decode('utf-8', errors='replace')
        stderr_text = result.stderr.decode('utf-8', errors='replace')
        
        if result.returncode != 0:
            print(f"  [!] Error running Python triage inside container (exit code {result.returncode})")
            print(f"STDOUT:\n{stdout_text}")
            print(f"STDERR:\n{stderr_text}")
        elif stdout_text:
            for line in stdout_text.splitlines():
                if line.startswith("DEBUG:") or "Error" in line or "Exception" in line:
                    print(f"  [container] {line}")
    except subprocess.TimeoutExpired:
        print(f"  [!] Timeout executing triage script inside container")
    except Exception as e:
        print(f"  [!] Error running docker run: {e}")
        
    tte_ms = None
    matching_crash = None
    
    if os.path.exists(result_path):
        with open(result_path, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
            if lines and lines[0] == "FOUND":
                tte_ms = int(lines[1])
                matching_crash = lines[2]
                
    # Copy full logs to the host's artifact directory
    if dest_logs_dir:
        host_logs_dir = os.path.join(local_crashes_dir, "full_logs")
        if os.path.exists(host_logs_dir):
            try:
                if os.path.exists(dest_logs_dir):
                    shutil.rmtree(dest_logs_dir)
                os.makedirs(os.path.dirname(dest_logs_dir), exist_ok=True)
                shutil.move(host_logs_dir, dest_logs_dir)
                print(f"  [+] Copied full logs to {dest_logs_dir}")
            except Exception as e:
                print(f"  [!] Failed to move full logs to {dest_logs_dir}: {e}")

    for p in [trace_path, triage_script_path, result_path, dest_triage_lib]:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass
                
    return tte_ms, matching_crash

def main():
    parser = argparse.ArgumentParser(description="Calculate true Time to Exposure (TTE) by checking crash backtraces.")
    parser.add_argument("--bench", required=True, help="Full benchmark directory name (e.g. libming-4.8.1_swftophp_CVE-2019-9114)")
    parser.add_argument("--root", default="./artifact", help="Root directory of the CVE artifact data")
    parser.add_argument("--build", action="store_true", help="Force rebuild of Docker images")
    parser.add_argument("--update-reached", action="store_true", help="Deprecated/Compatibility flag")
    parser.add_argument("--trial-name", type=str, help="Specific trial run name to check. If not specified, the latest one will be used.")
    args = parser.parse_args()

    # Locate artifact directory
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
    if trial_name:
        trial_name_base = re.sub(r'_\d{8}_\d{6}$', '', trial_name)
    else:
        trial_name_base = None

    if not trial_name_base:
        def get_trial_mtime(tn):
            times = [os.path.getmtime(os.path.join(artifact_dir, d)) for d in os.listdir(artifact_dir) if re.match(r"^" + re.escape(tn) + r"(_\d{8}_\d{6})?$", d)]
            return max(times) if times else 0
        trial_names_list = list(trial_names)
        trial_names_list.sort(key=get_trial_mtime, reverse=True)
        trial_name_base = trial_names_list[0]
        trial_name = trial_name_base
        print(f"No --trial-name specified. Automatically selected the latest trial: {trial_name_base}")
    else:
        if trial_name_base not in trial_names:
            print(f"Error: Specified trial-name '{trial_name}' not found under {artifact_dir}. Available base names: {list(trial_names)}")
            sys.exit(1)
            
    # Find matching session directories
    session_dirs = []
    for d in os.listdir(artifact_dir):
        if os.path.isdir(os.path.join(artifact_dir, d)) and d not in ["plot", "TTE_check"]:
            if re.match(r"^" + re.escape(trial_name_base) + r"(_\d{8}_\d{6})?$", d):
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

    # 1. Locate benchmark directory
    bench_dir = os.path.join("bench", args.bench)
    if not os.path.exists(bench_dir):
        print(f"Error: Benchmark directory {bench_dir} not found.")
        sys.exit(1)
        
    # 2. Parse trace file
    trace_path = os.path.join(bench_dir, "trace")
    target_trace = parse_trace(trace_path)
    if not target_trace:
        print(f"Error: Could not parse target trace from {trace_path}. Exiting.")
        sys.exit(1)
    print(f"Target stack trace to match: {target_trace}")
        
    # 3. Parse fuzzer command from .env
    cmd_str = parse_fuzzer_command(bench_dir)
    if not cmd_str:
        print(f"Error: Could not find fuzzer execution command in {bench_dir}/.env. Exiting.")
        sys.exit(1)
        
    parts = cmd_str.split()
    binary = parts[0]
    flags = parts[1:]
    print(f"Detected fuzzer command execution: {binary} with arguments {flags}")
    
    # Process each method
    for method in methods:
        print(f"\n================ Method: {method} ================")
        
        orig_image_name = get_docker_image_name(bench_dir, method)
        if not orig_image_name:
            print(f"Error: Could not find Docker image name for method {method} in compose files. Skipping.")
            continue
            
        image_name = orig_image_name.replace("-dd", "-multistage")
        if not image_name.endswith("-multistage:latest") and not image_name.endswith("-multistage"):
            image_name = re.sub(r'-dd(:|$)', '-multistage\\1', orig_image_name)
        print(f"Docker image mapped for {method} (using multistage version): {image_name}")
        
        image_exists = check_image_exists(image_name)
        if not image_exists:
            print(f"Docker image {image_name} not found locally.")
            continue
        else:
            print(f"Docker image {image_name} is available locally.")
            
        for item in trial_items:
            local_trial_dir = os.path.join(artifact_dir, item["session_dir"], method, item["trial"])
            if "dual-cd" in method:
                fuzzer_name = "cd"
            elif "dual-dd" in method:
                fuzzer_name = "dd"
            else:
                fuzzer_name = "main"
            local_crashes_dir = os.path.join(local_trial_dir, f"out/{fuzzer_name}/crashes")
            exposure_file_path = os.path.join(local_trial_dir, "dgf_target_exposure.txt")
            
            if not os.path.exists(local_crashes_dir):
                print(f"Trial {item['label']}: Crashes directory not found at {local_crashes_dir}. Writing TTE: inf.")
                with open(exposure_file_path, "w") as ef:
                    ef.write("Target not reached\n")
                continue
                
            crash_files = [f for f in os.listdir(local_crashes_dir) if f.startswith("id:")]
            if not crash_files:
                print(f"Trial {item['label']}: No crash files found. Writing TTE: inf.")
                with open(exposure_file_path, "w") as ef:
                    ef.write("Target not reached\n")
                continue
                
            def get_crash_time(filename):
                time_match = re.search(r'time:(\d+)', filename)
                return int(time_match.group(1)) if time_match else float('inf')
                
            crash_files.sort(key=get_crash_time)
            
            print(f"Trial {item['label']}: Triaging {len(crash_files)} crash files in a single container run...")
            
            if binary.endswith("-base"):
                asan_binary = binary[:-5] + "-asan"
            else:
                asan_binary = f"{binary}-asan"
                
            dest_logs_dir = os.path.join(artifact_dir, item["session_dir"], "TTE_check", f"{method}_{item['trial']}_full_logs")
            
            tte_ms, matching_crash = triage_crashes_in_container(
                image_name=image_name,
                binary=asan_binary,
                flags=flags,
                local_crashes_dir=local_crashes_dir,
                target_trace=target_trace,
                dest_logs_dir=dest_logs_dir
            )
            
            if tte_ms is not None:
                tte_sec = tte_ms / 1000.0
                print(f"  [+] Trial {item['label']} True TTE: {tte_sec:.3f} seconds ({tte_ms} ms) | Crash: {matching_crash}")
                with open(exposure_file_path, "w") as ef:
                    ef.write("Target reached!\n")
                    ef.write(f"Elapsed:    {tte_sec:.3f} seconds ({tte_ms} ms)\n")
                    ef.write(f"Crash File: {matching_crash}\n")
            else:
                print(f"  [-] Trial {item['label']} target was not reached by any crash.")
                with open(exposure_file_path, "w") as ef:
                    ef.write("Target not reached\n")

if __name__ == '__main__':
    main()

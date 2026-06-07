#!/usr/bin/env python3
import os
import re
import sys
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

def parse_fuzzer_command(benchmark_dir):
    """
    Parses script.sh in the benchmark directory to extract the fuzzer execution command.
    """
    script_path = os.path.join(benchmark_dir, "script.sh")
    if not os.path.exists(script_path):
        return None
    with open(script_path, 'r') as f:
        for line in f:
            if "afl-fuzz" in line:
                match = re.search(r'--\s+(.+)$', line)
                if match:
                    cmd_str = match.group(1).strip()
                    # Strip trailing quotes if the whole fuzzer command was quoted
                    cmd_str = cmd_str.strip('"').strip("'")
                    return cmd_str
    return None

def get_docker_image_name(benchmark_dir, method):
    """
    Extracts the built image name for the specified method from the compose files.
    """
    compose_files = []
    if os.path.exists(benchmark_dir):
        for f in os.listdir(benchmark_dir):
            if (f.endswith(".yaml") or f.endswith(".yml")) and "compose" in f:
                compose_files.append(os.path.join(benchmark_dir, f))
    
    target_files = []
    if "icd" in method:
        target_files.append("base+icd.compose.yaml")
        target_files.append("base+icd.compose.yml")
    else:
        target_files.append("base.compose.yaml")
        target_files.append("base.compose.yml")
        target_files.append("compose.yaml")
        target_files.append("compose.yml")
        
    for tf in target_files:
        p = os.path.join(benchmark_dir, tf)
        if os.path.exists(p):
            with open(p, 'r') as f:
                for line in f:
                    match = re.search(r'image:\s*([^\s]+)', line)
                    if match:
                        return match.group(1).strip()
                        
    for fpath in compose_files:
        with open(fpath, 'r') as f:
            content = f.read()
            images = re.findall(r'image:\s*([^\s]+)', content)
            if images:
                for img in images:
                    if "icd" in method and "icd" in img:
                        return img
                    if ("origin" in method or "base" in method) and ("base" in img or "origin" in img):
                        return img
                return images[0]
    return None

def check_image_exists(image_name):
    """
    Checks if the specified docker image is present locally.
    """
    try:
        res = subprocess.run(["docker", "image", "inspect", image_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def build_docker_images(benchmark_dir):
    """
    Triggers docker compose build inside the benchmark directory.
    """
    print(f"Building Docker images in {benchmark_dir}...")
    try:
        # Check compose.yaml first
        compose_path = os.path.join(benchmark_dir, "compose.yaml")
        if os.path.exists(compose_path):
            subprocess.run(["docker", "compose", "-f", compose_path, "build"], check=True)
            return True
        
        # Fallback to other compose files in the folder
        built = False
        for f in os.listdir(benchmark_dir):
            if f.endswith(".compose.yaml") or f.endswith(".compose.yml"):
                subprocess.run(["docker", "compose", "-f", os.path.join(benchmark_dir, f), "build"], check=True)
                built = True
        return built
    except Exception as e:
        print(f"Error building Docker images: {e}")
        return False

def triage_crashes_in_container(image_name, binary, flags, local_crashes_dir, target_trace):
    """
    Writes a helper script and runs GDB on all crash files inside a single
    temporary Docker container run to drastically improve performance.
    """
    local_crashes_dir = os.path.abspath(local_crashes_dir)
    
    # 1. Write target_trace to .target_trace on the host
    trace_path = os.path.join(local_crashes_dir, ".target_trace")
    with open(trace_path, 'w') as f:
        for t in target_trace:
            f.write(t + "\n")
            
    triage_script_content = """import os
import re
import subprocess
import sys

def get_crash_time(filename):
    time_match = re.search(r'time:(\\d+)', filename)
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
    
    match_required = min(len(target_trace), 3)
    
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
        except Exception:
            continue
            
        frames = []
        for line in bt_text.splitlines():
            m = re.search(r'([\\w\\-]+\\.[c|h]):(\\d+)', line)
            if m:
                frames.append(f"{m.group(1)}:{m.group(2)}")
                
        found_match = False
        start_indices = [idx for idx, f in enumerate(frames) if is_frame_match(f, target_trace[0])]
        
        if start_indices:
            print(f"DEBUG: {crash_file} matched target_trace[0] ({target_trace[0]}) at frame indices {start_indices}")
            print(f"DEBUG: Full backtrace frames for {crash_file}: {frames}")
            
        for start_idx in start_indices:
            matched_count = 1
            curr_idx = start_idx + 1
            matched_subset = [frames[start_idx]]
            for target in target_trace[1:]:
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
            f.write(f"FOUND\\n{tte_ms}\\n{matching_crash}\\n")
        else:
            f.write("NOT_FOUND\\n")

if __name__ == '__main__':
    main()
"""
    triage_script_path = os.path.join(local_crashes_dir, ".triage.py")
    with open(triage_script_path, 'w') as f:
        f.write(triage_script_content)
        
    # Remove any existing .triage_result on the host
    result_path = os.path.join(local_crashes_dir, ".triage_result")
    if os.path.exists(result_path):
        os.remove(result_path)
        
    # 3. Run the container exactly once
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
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        stdout_text = result.stdout.decode('utf-8', errors='replace')
        stderr_text = result.stderr.decode('utf-8', errors='replace')
        
        # If there are any output lines from python execution that indicate error
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
        
    # 4. Parse results from .triage_result on the host
    tte_ms = None
    matching_crash = None
    
    if os.path.exists(result_path):
        with open(result_path, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
            if lines and lines[0] == "FOUND":
                tte_ms = int(lines[1])
                matching_crash = lines[2]
                
    # 5. Clean up temporary files on the host
    for p in [trace_path, triage_script_path, result_path]:
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
    parser.add_argument("--update-reached", action="store_true", help="Deprecated/Compatibility flag (does not write to dgf_target_reached.txt anymore)")
    args = parser.parse_args()

    # 1. Locate benchmark directory
    bench_dir = os.path.join("bench", "ICD", args.bench)
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
        
    # 3. Parse fuzzer command from script.sh
    cmd_str = parse_fuzzer_command(bench_dir)
    if not cmd_str:
        print(f"Error: Could not find fuzzer execution command in {bench_dir}/script.sh. Exiting.")
        sys.exit(1)
        
    parts = cmd_str.split()
    binary = parts[0]
    flags = parts[1:]
    print(f"Detected fuzzer command execution: {binary} with arguments {flags}")
    
    # 4. Locate fuzzer method directories under artifact
    artifact_dir = os.path.join(args.root, args.bench)
    if not os.path.exists(artifact_dir):
        print(f"Error: Artifact directory {artifact_dir} not found. Exiting.")
        sys.exit(1)
        
    methods = [d for d in os.listdir(artifact_dir) if os.path.isdir(os.path.join(artifact_dir, d)) and d != "plot"]
    if not methods:
        print(f"Error: No fuzzer method directories found under {artifact_dir}. Exiting.")
        sys.exit(1)
    print(f"Detected fuzzer methods: {methods}")
    
    # 5. Process each method
    for method in methods:
        print(f"\n================ Method: {method} ================")
        
        # Get Docker image name for this method
        image_name = get_docker_image_name(bench_dir, method)
        if not image_name:
            print(f"Error: Could not find Docker image name for method {method} in compose files. Skipping.")
            continue
            
        print(f"Docker image mapped for {method}: {image_name}")
        
        # Check / build Docker image
        image_exists = check_image_exists(image_name)
        if not image_exists or args.build:
            if not image_exists:
                print(f"Docker image {image_name} not found locally.")
            else:
                print(f"Force build specified. Rebuilding images...")
            success = build_docker_images(bench_dir)
            if not success:
                print(f"Failed to build Docker images. Skipping method {method}.")
                continue
        else:
            print(f"Docker image {image_name} is available locally.")
            
        method_dir = os.path.join(artifact_dir, method)
        trials = [t for t in os.listdir(method_dir) if os.path.isdir(os.path.join(method_dir, t)) and t.startswith("trial")]
        
        def sort_key(x):
            digits = re.search(r'\d+', x)
            return (0, int(digits.group())) if digits else (1, x)
        trials.sort(key=sort_key)
        
        if not trials:
            print(f"No trial folders found under {method_dir}. Skipping.")
            continue
            
        print(f"Found trials to triage: {trials}")
        
        for trial in trials:
            local_trial_dir = os.path.join(method_dir, trial)
            local_crashes_dir = os.path.join(local_trial_dir, "out/main/crashes")
            exposure_file_path = os.path.join(local_trial_dir, "dgf_target_exposure.txt")
            
            if not os.path.exists(local_crashes_dir):
                print(f"Trial {trial}: Crashes directory not found at {local_crashes_dir}. Writing TTE: inf.")
                with open(exposure_file_path, "w") as ef:
                    ef.write("Target not reached\n")
                continue
                
            # List local crash files
            crash_files = [f for f in os.listdir(local_crashes_dir) if f.startswith("id:")]
            if not crash_files:
                print(f"Trial {trial}: No crash files found. Writing TTE: inf.")
                with open(exposure_file_path, "w") as ef:
                    ef.write("Target not reached\n")
                continue
                
            # Sort crashes by fuzzer elapsed time in filename
            def get_crash_time(filename):
                time_match = re.search(r'time:(\d+)', filename)
                return int(time_match.group(1)) if time_match else float('inf')
                
            crash_files.sort(key=get_crash_time)
            
            print(f"Trial {trial}: Triaging {len(crash_files)} crash files in a single container run...")
            
            # Execute triage inside a single container run
            tte_ms, matching_crash = triage_crashes_in_container(
                image_name=image_name,
                binary=binary,
                flags=flags,
                local_crashes_dir=local_crashes_dir,
                target_trace=target_trace
            )
            
            # Write exposure results
            if tte_ms is not None:
                tte_sec = tte_ms / 1000.0
                print(f"  [+] Trial {trial} True TTE: {tte_sec:.3f} seconds ({tte_ms} ms) | Crash: {matching_crash}")
                with open(exposure_file_path, "w") as ef:
                    ef.write("Target reached!\n")
                    ef.write(f"Elapsed:    {tte_sec:.3f} seconds ({tte_ms} ms)\n")
                    ef.write(f"Crash File: {matching_crash}\n")
            else:
                print(f"  [-] Trial {trial} target was not reached by any crash.")
                with open(exposure_file_path, "w") as ef:
                    ef.write("Target not reached\n")

if __name__ == '__main__':
    main()

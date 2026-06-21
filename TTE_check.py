#!/usr/bin/env python3
import os
import re
import sys
import subprocess
import argparse

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
    script_path = os.path.join(benchmark_dir, "script.sh")
    if not os.path.exists(script_path):
        return None
    
    target_default = None
    with open(script_path, 'r') as f:
        content = f.read()
        
    m_tar = re.search(r'TARGET=\${TARGET_BIN:-([^}]+)}', content)
    if m_tar:
        target_default = m_tar.group(1).strip()
        
    for line in content.split('\n'):
        if "afl-fuzz" in line or "$FUZZER" in line:
            match = re.search(r'--\s+(.+)$', line)
            if match:
                cmd_str = match.group(1).strip()
                cmd_str = cmd_str.strip('"').strip("'")
                if "$TARGET" in cmd_str and target_default:
                    cmd_str = cmd_str.replace("$TARGET", target_default)
                return cmd_str
    return None

def get_docker_image_name(benchmark_dir, method):
    compose_files = []
    if os.path.exists(benchmark_dir):
        for f in os.listdir(benchmark_dir):
            if (f.endswith(".yaml") or f.endswith(".yml")) and "compose" in f:
                compose_files.append(os.path.join(benchmark_dir, f))
    
    target_files = []
    if "dual" in method:
        target_files = [
            "dual.compose.yaml", "dual.compose.yml",
            "cd.compose.yaml", "cd.compose.yml",
            "dd.compose.yaml", "dd.compose.yml"
        ]
    elif "cd" in method:
        target_files = [
            "cd.compose.yaml", "cd.compose.yml",
            "dual.compose.yaml", "dual.compose.yml"
        ]
    elif "dd" in method:
        target_files = [
            "dd.compose.yaml", "dd.compose.yml",
            "dual.compose.yaml", "dual.compose.yml"
        ]
    elif "base" in method:
        target_files = [
            "base.compose.yaml", "base.compose.yml",
            "compose.yaml", "compose.yml"
        ]
    else:
        target_files = [
            "compose.yaml", "compose.yml"
        ]
        
    def matches_method(img, meth):
        img_lower = img.lower()
        meth_lower = meth.lower()
        if "dual-cd" in meth_lower:
            return "cd" in img_lower or "dd" in img_lower or "multistage" in img_lower
        elif "cd" in meth_lower:
            return "cd" in img_lower or "cafl" in img_lower or "multistage" in img_lower
        elif "dd" in meth_lower:
            return "dd" in img_lower or "dafl" in img_lower or "multistage" in img_lower
        elif "base" in meth_lower:
            return "base" in img_lower or "multistage" in img_lower
        else:
            return "multistage" in img_lower or ("cafl" not in img_lower and "dafl" not in img_lower)

    for tf in target_files:
        p = os.path.join(benchmark_dir, tf)
        if os.path.exists(p):
            with open(p, 'r') as f:
                content = f.read()
                images = re.findall(r'image:\s*([^\s]+)', content)
                for img in images:
                    img_clean = img.strip().strip('"').strip("'")
                    if matches_method(img_clean, method):
                        return img_clean
                        
    for fpath in compose_files:
        with open(fpath, 'r') as f:
            content = f.read()
            images = re.findall(r'image:\s*([^\s]+)', content)
            for img in images:
                img_clean = img.strip().strip('"').strip("'")
                if matches_method(img_clean, method):
                    return img_clean
                
    return None

def check_image_exists(image_name):
    try:
        res = subprocess.run(["docker", "image", "inspect", image_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def build_docker_images(benchmark_dir):
    print(f"Building Docker images in {benchmark_dir}...")
    try:
        compose_path = os.path.join(benchmark_dir, "compose.yaml")
        if os.path.exists(compose_path):
            subprocess.run(["docker", "compose", "-f", compose_path, "build"], check=True)
            return True
        
        built = False
        for f in os.listdir(benchmark_dir):
            if f.endswith(".compose.yaml") or f.endswith(".compose.yml"):
                subprocess.run(["docker", "compose", "-f", os.path.join(benchmark_dir, f), "build"], check=True)
                built = True
        return built
    except Exception as e:
        print(f"Error building Docker images: {e}")
        return False

def triage_crashes_in_container(image_name, binary, flags, local_crashes_dir, target_trace, cve_name="", method="", trial="", root_dir="./artifact"):
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

    triage_script_content = triage_script_content.replace("PLACEHOLDER_CVE_NAME", cve_name)

    # Copy triage.py library to local_crashes_dir so the container can import it
    triage_lib_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "triage.py")
    dest_triage_lib = os.path.join(local_crashes_dir, "triage.py")
    import shutil
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
    if method and trial:
        host_logs_dir = os.path.join(local_crashes_dir, "full_logs")
        if os.path.exists(host_logs_dir):
            dest_logs_dir = os.path.join(root_dir, cve_name, "TTE_check", method, f"{trial}_full_logs")
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
    args = parser.parse_args()

    # Locate artifact directory
    artifact_dir = os.path.join(args.root, args.bench)
    if not os.path.exists(artifact_dir):
        print(f"Error: Artifact directory {artifact_dir} not found. Exiting.")
        sys.exit(1)
        
    methods = [d for d in os.listdir(artifact_dir) if os.path.isdir(os.path.join(artifact_dir, d)) and d != "plot"]
    if not methods:
        print(f"Error: No fuzzer method directories found under {artifact_dir}. Exiting.")
        sys.exit(1)
    print(f"Detected fuzzer methods: {methods}")

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
        if not image_exists or args.build:
            if not image_exists:
                print(f"Docker image {image_name} not found locally.")
            else:
                print(f"Force build specified. Rebuilding image...")
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
            if "dual-cd" in method:
                fuzzer_name = "cd"
            elif "dual-dd" in method:
                fuzzer_name = "dd"
            else:
                fuzzer_name = "main"
            local_crashes_dir = os.path.join(local_trial_dir, f"out/{fuzzer_name}/crashes")
            exposure_file_path = os.path.join(local_trial_dir, "dgf_target_exposure.txt")
            
            if not os.path.exists(local_crashes_dir):
                print(f"Trial {trial}: Crashes directory not found at {local_crashes_dir}. Writing TTE: inf.")
                with open(exposure_file_path, "w") as ef:
                    ef.write("Target not reached\n")
                continue
                
            crash_files = [f for f in os.listdir(local_crashes_dir) if f.startswith("id:")]
            if not crash_files:
                print(f"Trial {trial}: No crash files found. Writing TTE: inf.")
                with open(exposure_file_path, "w") as ef:
                    ef.write("Target not reached\n")
                continue
                
            def get_crash_time(filename):
                time_match = re.search(r'time:(\d+)', filename)
                return int(time_match.group(1)) if time_match else float('inf')
                
            crash_files.sort(key=get_crash_time)
            
            print(f"Trial {trial}: Triaging {len(crash_files)} crash files in a single container run...")
            
            asan_binary = f"{binary}-asan"
            tte_ms, matching_crash = triage_crashes_in_container(
                image_name=image_name,
                binary=asan_binary,
                flags=flags,
                local_crashes_dir=local_crashes_dir,
                target_trace=target_trace,
                cve_name=args.bench,
                method=method,
                trial=trial,
                root_dir=args.root
            )
            
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

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

def check_image_exists(image_name, cve_name=None):
    import shutil
    if shutil.which("docker"):
        try:
            res = subprocess.run(["docker", "image", "inspect", image_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return res.returncode == 0
        except Exception:
            return False
    else:
        if not cve_name:
            return False
        scripts_dir = os.path.dirname(os.path.realpath(__file__))
        root_dir = os.path.dirname(scripts_dir)
        bench_dir = os.path.join(root_dir, "bench", cve_name)
        env_image_name = get_docker_image_name(bench_dir, None)
        if not env_image_name:
            return False
        sif_path = os.path.join(bench_dir, f"{env_image_name}.sif")
        return os.path.exists(sif_path)

def triage_crashes_in_container(image_name, binary, flags, local_crashes_dir, target_trace, cve_name, dest_logs_dir=None):
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
    shutil.copy(triage_lib_path, dest_triage_lib)

    triage_script_path = os.path.join(local_crashes_dir, ".triage.py")
    with open(triage_script_path, 'w') as f:
        f.write(triage_script_content)
        
    result_path = os.path.join(local_crashes_dir, ".triage_result")
    if os.path.exists(result_path):
        os.remove(result_path)
        
    triaged_record_path = os.path.join(local_crashes_dir, ".triaged_crashes")
    if os.path.exists(triaged_record_path):
        os.remove(triaged_record_path)

    if shutil.which("docker"):
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
    else:
        import getpass
        import atexit
        import time

        username = getpass.getuser()
        pid = os.getpid()
        
        shm_base = f"/dev/shm/{username}_triage_{pid}"
        shm_cache = os.path.join(shm_base, "cache")
        shm_tmp = os.path.join(shm_base, "tmp")
        
        os.makedirs(shm_cache, exist_ok=True)
        os.makedirs(shm_tmp, exist_ok=True)
        
        os.environ["APPTAINER_CACHEDIR"] = shm_cache
        os.environ["APPTAINER_TMPDIR"] = shm_tmp

        def cleanup_shm():
            print(f"\n[+] cleaning RAM Disk: {shm_base}")
            shutil.rmtree(shm_base, ignore_errors=True)
        atexit.register(cleanup_shm)

        scripts_dir = os.path.dirname(os.path.realpath(__file__))
        root_dir = os.path.dirname(scripts_dir)
        bench_dir = os.path.join(root_dir, "bench", cve_name)
        
        env_image_name = get_docker_image_name(bench_dir, None)
        if not env_image_name:
            print(f"Error: Could not find IMAGE_NAME in {bench_dir}/.env for Apptainer fallback.")
            sys.exit(1)
            
        orig_sif_path = os.path.join(bench_dir, f"{env_image_name}.sif")
        if not os.path.exists(orig_sif_path):
            print(f"Error: Apptainer image {orig_sif_path} not found.")
            sys.exit(1)
        
        ram_sandbox_path = os.path.join(shm_base, f"{env_image_name}_sandbox")
        if not os.path.exists(ram_sandbox_path):
            print(f"[+] Extracting Apptainer sandbox directly to RAM Disk: {ram_sandbox_path}")
            try:
                subprocess.run(
                    ["apptainer", "build", "--sandbox", ram_sandbox_path, orig_sif_path],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except subprocess.CalledProcessError as e:
                print(f"Error: Failed to extract sandbox to RAM. {e}")
                sys.exit(1)
        
        print(f"[+] Apptainer Sandbox ready in RAM: {ram_sandbox_path}")
        cmd = [
            "apptainer", "exec",
            "--cleanenv",
            "--containall",
            "--pid",
            "--ipc",
            "--no-home",
            "--bind", f"{local_crashes_dir}:/workspace/out/main/crashes",
            ram_sandbox_path,
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
    finally:
        try:
            host_uid = os.getuid() if hasattr(os, 'getuid') else 0
            host_gid = os.getgid() if hasattr(os, 'getgid') else 0
            subprocess.run(["sudo", "-n", "chown", "-R", f"{host_uid}:{host_gid}", local_crashes_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        
    tte_ms = None
    matching_crash = None
    
    if os.path.exists(result_path):
        with open(result_path, 'r') as f:
            res = f.read().strip()
            if res and res != "None":
                if res.startswith("ERROR"):
                    print("="*60)
                    print(f"CRITICAL ERROR: Triage process encountered failure inside the container:")
                    print(res)
                    print("="*60)
                    sys.exit(1)
                else:
                    parts = res.rsplit(',', 1)
                    if len(parts) == 2:
                        matching_crash = parts[0]
                        tte_ms = int(parts[1])
    stats_path = os.path.join(local_crashes_dir, ".triage_stats")
    if os.path.exists(stats_path):
        try:
            with open(stats_path, 'r') as f:
                parts = f.read().strip().split(",")
                if len(parts) == 3:
                    count = int(parts[0])
                    avg_ms = float(parts[1]) * 1000.0
                    max_ms = float(parts[2]) * 1000.0
                    if count > 0:
                        print(f"  [+] Triage performance: checked {count} cases | avg: {avg_ms:.1f} ms | max: {max_ms:.1f} ms")
        except Exception:
            pass
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
    if trial_name and trial_name.lower() != 'all':
        trial_name_base = re.sub(r'_\d{8}_\d{6}$', '', trial_name)
    else:
        trial_name_base = None

    if not trial_name_base:
        session_dirs = []
        for d in os.listdir(artifact_dir):
            if os.path.isdir(os.path.join(artifact_dir, d)) and d not in ["plot", "TTE_check"]:
                session_dirs.append(d)
        if not session_dirs:
            print(f"Error: No trial runs found under {artifact_dir}. Exiting.")
            sys.exit(1)
        trial_name = "all"
        trial_name_base = "all"
    else:
        if trial_name_base not in trial_names:
            print(f"Error: Specified trial-name '{trial_name}' not found under {artifact_dir}. Available base names: {list(trial_names)}")
            sys.exit(1)
            
        # Find matching session directories
        session_dirs = []
        for d in os.listdir(artifact_dir):
            if os.path.isdir(os.path.join(artifact_dir, d)) and d not in ["plot", "TTE_check"]:
                if d == trial_name:
                    session_dirs.append(d)
                elif not re.search(r'_\d{8}_\d{6}$', trial_name) and re.match(r"^" + re.escape(trial_name_base) + r"(_\d{8}_\d{6})?$", d):
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
        
        image_exists = check_image_exists(image_name, cve_name=args.bench)
        import shutil
        if not image_exists:
            if shutil.which("docker"):
                print(f"Docker image {image_name} not found locally.")
            else:
                print(f"Apptainer image for {args.bench} not found locally.")
            continue
        else:
            if shutil.which("docker"):
                print(f"Docker image {image_name} is available locally.")
            else:
                print(f"Apptainer image for {args.bench} is available locally.")
            
        for item in trial_items:
            local_trial_dir = os.path.join(artifact_dir, item["session_dir"], method, item["trial"])
            os.makedirs(local_trial_dir, exist_ok=True)
            exposure_file_path = os.path.join(local_trial_dir, "dgf_target_exposure.txt")
            
            # Locate all sub-crashes directories
            crashes_dirs = []
            master_crashes_dir = os.path.join(local_trial_dir, f"out/{method}/crashes")
            if os.path.exists(master_crashes_dir):
                crashes_dirs.append(("main", master_crashes_dir))
                    
            best_tte_ms = None
            best_matching_crash = None
            
            # If no crashes directories exist at all
            if not crashes_dirs:
                print(f"Trial {item['label']}: Crashes directory not found. Writing TTE: inf.")
                with open(exposure_file_path, "w") as ef:
                    ef.write("Target not reached\n")
                continue
                
            # Triage each crashes directory
            for name, local_crashes_dir in crashes_dirs:
                crash_files = [f for f in os.listdir(local_crashes_dir) if f.startswith("id:")]
                if not crash_files:
                    continue
                    
                def get_crash_time(filename):
                    time_match = re.search(r'time:(\d+)', filename)
                    return int(time_match.group(1)) if time_match else float('inf')
                    
                crash_files.sort(key=get_crash_time)
                
                print(f"Trial {item['label']} ({name}): Triaging {len(crash_files)} crash files in a single container run...")
                
                # Strip leading paths if necessary, but actually the .env specifies the path like ./cxxfilt-base
                # We need the ASAN version.
                if binary.endswith("-base"):
                    asan_binary = binary[:-5] + "-asan"
                else:
                    # If it doesn't end with -base, just append -asan (or handle specific cases)
                    asan_binary = f"{binary}-asan"
                    
                # Fix for paths: if it starts with ./, it's relative to /workspace inside the container.
                # The container execution already binds and works in the right context or uses the absolute path if provided.
                # Actually, TTE_check.py explicitly calls it from the command line in Docker. Let's make it absolute.
                if asan_binary.startswith("./"):
                    asan_binary = "/workspace/" + asan_binary[2:]
                    
                dest_logs_dir = os.path.join(artifact_dir, item["session_dir"], "TTE_check", f"{method}_{item['trial']}_{name}_full_logs")
                
                tte_ms, matching_crash = triage_crashes_in_container(
                    image_name=image_name,
                    binary=asan_binary,
                    flags=flags,
                    local_crashes_dir=local_crashes_dir,
                    target_trace=target_trace,
                    cve_name=args.bench,
                    dest_logs_dir=dest_logs_dir
                )
                
                if tte_ms is not None:
                    if best_tte_ms is None or tte_ms < best_tte_ms:
                        best_tte_ms = tte_ms
                        best_matching_crash = f"{name}/{matching_crash}"
                        
            if best_tte_ms is not None:
                tte_sec = best_tte_ms / 1000.0
                print(f"  [+] Trial {item['label']} True TTE: {tte_sec:.3f} seconds ({best_tte_ms} ms) | Crash: {best_matching_crash}")
                with open(exposure_file_path, "w") as ef:
                    ef.write("Target reached!\n")
                    ef.write(f"Elapsed:    {tte_sec:.3f} seconds ({best_tte_ms} ms)\n")
                    ef.write(f"Crash File: {best_matching_crash}\n")
            else:
                print(f"  [-] Trial {item['label']} target was not reached by any crash.")
                with open(exposure_file_path, "w") as ef:
                    ef.write("Target not reached\n")

if __name__ == '__main__':
    main()

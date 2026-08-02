#!/usr/bin/env python3
import os
import re
import sys
import subprocess
import argparse
import shutil
import time

def parse_trace(trace_path):
    trace = []
    if not os.path.exists(trace_path):
        return trace
    with open(trace_path, 'r') as f:
        for line in f:
            line = line.strip()
            line = re.sub(r'^\d+:\s*', '', line)
            if line:
                trace.append(line)
    return trace

def get_container_env(container_name):
    res = subprocess.run(["docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", container_name], capture_output=True, text=True)
    env_vars = {}
    if res.returncode == 0:
        for line in res.stdout.splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                env_vars[k.strip()] = v.strip()
    return env_vars

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bench", required=True)
    parser.add_argument("--root", default="./artifact")
    args = parser.parse_args()

    cve = args.bench
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bench_dir = os.path.join(root_dir, "bench", cve)
    
    # 1. Parse trace
    trace_path = os.path.join(bench_dir, "trace")
    target_trace = parse_trace(trace_path)
    if not target_trace:
        print(f"Error: Trace not found at {trace_path}")
        sys.exit(1)

    # 2. Get active containers
    res = subprocess.run(["docker", "ps", "--filter", f"name=^{cve}-afl-", "--format", "{{.Names}}"], capture_output=True, text=True)
    containers = [c.strip() for c in res.stdout.splitlines() if c.strip() and "-slave-" not in c]

    if not containers:
        print(f"No active containers found for {cve}.")
        sys.exit(0)

    # 3. Prepare triage script
    triage_helper_path = os.path.join(root_dir, "scripts", "container_triage.py")
    triage_lib_path = os.path.join(root_dir, "scripts", "triage.py")
    
    with open(triage_helper_path, 'r') as f:
        triage_script_content = f.read()
    triage_script_content = triage_script_content.replace("PLACEHOLDER_CVE_NAME", cve)
    
    tmp_dir = f"/tmp/live_triage_{cve}"
    os.makedirs(tmp_dir, exist_ok=True)
    
    local_trace_path = os.path.join(tmp_dir, ".target_trace")
    with open(local_trace_path, 'w') as f:
        for t in target_trace:
            f.write(t + "\n")
            
    local_script_path = os.path.join(tmp_dir, ".triage.py")
    with open(local_script_path, 'w') as f:
        f.write(triage_script_content)
        
    local_lib_path = os.path.join(tmp_dir, "triage.py")
    shutil.copy(triage_lib_path, local_lib_path)

    # 4. Check each container
    for c_name in containers:
        print(f"Checking live container: {c_name}...")
        env = get_container_env(c_name)
        trial_name = env.get("TRIAL_NAME")
        session_id = env.get("SESSION_ID")
        
        if not trial_name:
            print(f"  [!] Missing TRIAL_NAME in {c_name}")
            continue
            
        # Write .session_id if missing so manage.py copy doesn't create duplicate trials
        artifact_trial_dir = os.path.join(root_dir, "artifact", cve, trial_name)
        os.makedirs(artifact_trial_dir, exist_ok=True)
        if session_id:
            session_id_file = os.path.join(artifact_trial_dir, ".session_id")
            if not os.path.exists(session_id_file):
                with open(session_id_file, "w") as f:
                    f.write(session_id)

        # Extract method and trial_idx from container name
        # Format: {cve}-afl-{method}-{idx} or {cve}-afl-muoafl-{tag}-{idx}
        prefix = f"{cve}-afl-"
        if not c_name.startswith(prefix):
            continue
            
        parts = c_name[len(prefix):].rsplit('-', 1)
        if len(parts) != 2:
            continue
        method = parts[0]
        trial_idx = parts[1]
        
        # Determine ASAN binary and flags
        asan_binary = env.get("TARGET_BIN_ASAN")
        target_args = env.get("TARGET_ARGS", "")
        
        if not asan_binary:
            print(f"  [!] TARGET_BIN_ASAN not set in {c_name}")
            continue
            
        if asan_binary.startswith("./"):
            asan_binary = "/workspace/" + asan_binary[2:]
            
        flags = target_args.split()

        # Target directories in artifact
        dest_dir = os.path.join(root_dir, "artifact", cve, trial_name, method, f"trial{trial_idx}")
        os.makedirs(dest_dir, exist_ok=True)
        tte_file = os.path.join(dest_dir, "tte.txt")
        
        # Optional: check if already reached
        if os.path.exists(tte_file):
            with open(tte_file, "r") as f:
                content = f.read().strip()
                if content:
                    print(f"  [+] Target already reached for {c_name} (Crash: {content}). Skipping.")
                    continue

        crashes_dir = "/workspace/out/main/crashes"
        
        # Push files to container
        subprocess.run(["docker", "cp", local_trace_path, f"{c_name}:{crashes_dir}/.target_trace"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "cp", local_script_path, f"{c_name}:{crashes_dir}/.triage.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "cp", local_lib_path, f"{c_name}:{crashes_dir}/triage.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Check total crashes first to match sbatch.sh triage.log output
        res_ls = subprocess.run(["docker", "exec", c_name, "bash", "-c", f"ls {crashes_dir}/id:* 2>/dev/null | wc -l"], capture_output=True, text=True)
        total_crashes = 0
        if res_ls.returncode == 0:
            try:
                total_crashes = int(res_ls.stdout.strip())
            except ValueError:
                pass

        triage_log_path = os.path.join(dest_dir, "triage.log")
        
        if total_crashes == 0:
            msg = f"      [main] [Triage Stats] 0 total crashes found by Fuzzer so far.\n"
            with open(triage_log_path, "a") as lf:
                lf.write(f"[*] [{time.ctime()}] Running live triage...\n")
                lf.write(msg)
            print(f"  [-] {msg.strip()}")
            with open(tte_file, "w") as f:
                pass
            continue
            
        with open(triage_log_path, "a") as lf:
            lf.write(f"[*] [{time.ctime()}] Running live triage...\n")
            lf.write(f"      [main] Triaging {total_crashes} total crashes in {crashes_dir}...\n")

        # Execute triage script inside container
        cmd = ["docker", "exec", "-w", "/workspace", c_name, "python3", f"{crashes_dir}/.triage.py", asan_binary] + flags
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            # Write to triage.log
            with open(triage_log_path, "a") as lf:
                if res.stdout:
                    lf.write(res.stdout)
                if res.stderr:
                    lf.write(res.stderr)
            
            if res.returncode != 0:
                print(f"  [!] Error executing triage script in {c_name}:\n{res.stdout}\n{res.stderr}")
                continue
        except subprocess.TimeoutExpired:
            print(f"  [!] Timeout executing triage script in {c_name}")
            continue

        # Fetch result
        res_cat = subprocess.run(["docker", "exec", c_name, "cat", f"{crashes_dir}/.triage_result"], capture_output=True, text=True)
        if res_cat.returncode == 0:
            result = res_cat.stdout.strip()
            if result and result != "None":
                if result.startswith("ERROR"):
                    print(f"  [!] Triage error in {c_name}:\n{result}")
                else:
                    parts = result.rsplit(',', 1)
                    if len(parts) == 2:
                        matching_crash = f"main/{parts[0]}"
                        tte_ms = parts[1]
                        tte_sec = int(tte_ms) / 1000.0
                        print(f"  [+] Match found! True TTE: {tte_sec:.3f} seconds ({tte_ms} ms) | Crash: {matching_crash}")
                        
                        with open(triage_log_path, "a") as lf:
                            lf.write(f"[+] TTE Found! True TTE: {tte_sec:.3f} seconds ({tte_ms} ms) | Crash: {matching_crash}\n")
                            
                        with open(tte_file, "w") as f:
                            f.write(f"{matching_crash}\n")
                        continue
                        
        print(f"  [-] Target not reached yet in {c_name}.")
        # Create empty tte.txt to indicate it was checked but not reached
        with open(tte_file, "w") as f:
            pass

    shutil.rmtree(tmp_dir, ignore_errors=True)
    print("Live TTE check completed.")

if __name__ == '__main__':
    main()

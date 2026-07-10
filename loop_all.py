#!/usr/bin/env python3
import sys
import os
import subprocess
import time
import datetime
import argparse

def get_latest_success_rate(cve, root_dir):
    import re
    artifact_cve_dir = os.path.join(root_dir, "artifact", cve)
    if not os.path.isdir(artifact_cve_dir):
        return 0.0, 0, 0
        
    sessions = []
    for d in os.listdir(artifact_cve_dir):
        if os.path.isdir(os.path.join(artifact_cve_dir, d)) and d not in ["plot", "TTE_check"]:
            sessions.append(d)
            
    if not sessions:
        return 0.0, 0, 0
        
    def sort_session_key(x):
        ts_match = re.search(r'_(\d{8}_\d{6})$', x)
        return ts_match.group(1) if ts_match else ""
        
    sessions.sort(key=sort_session_key)
    latest_session = sessions[-1]
    latest_session_dir = os.path.join(artifact_cve_dir, latest_session)
    
    total_trials = 0
    reached_trials = 0
    
    for root, dirs, files in os.walk(latest_session_dir):
        for file in files:
            if file == "dgf_target_exposure.txt":
                total_trials += 1
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r") as f:
                        first_line = f.readline().strip()
                        if first_line == "Target reached!":
                            reached_trials += 1
                except Exception:
                    pass
                    
    if total_trials == 0:
        return 0.0, 0, 0
        
    return reached_trials / total_trials, reached_trials, total_trials

def main():
    root_dir = os.path.abspath(os.path.dirname(__file__))
    
    # Automatically re-execute within the virtualenv if it exists and we're not inside it
    venv_python = os.path.abspath(os.path.join(root_dir, "../.venv/bin/python3"))
    if os.path.isfile(venv_python) and os.path.abspath(sys.executable) != venv_python:
        os.execv(venv_python, [venv_python] + sys.argv)
        
    parser = argparse.ArgumentParser(description="Continuous Trial Runner Loop for All CVEs")
    parser.add_argument("iterations", type=int, help="Number of iterations to run the full CVE loop")
    parser.add_argument("--trials", type=int, default=15, help="Number of trials per CVE (default: 15)")
    parser.add_argument("--slurm", action="store_true", help="Run in Slurm mode using manage_slurm.py")
    args = parser.parse_args()
    
    iterations = args.iterations
    trials = args.trials
    
    # Import get_cves from manage.py
    sys.path.append(root_dir)
    try:
        from manage import get_cves
    except ImportError as e:
        print(f"Error: Failed to import get_cves from manage.py. Details: {e}")
        sys.exit(1)
        
    cve_list = get_cves(root_dir)
    if not cve_list:
        print("Error: No active CVEs found in cves.env or cves.env.template.")
        sys.exit(1)
        
    print(f"\033[1;32m[Loop Runner All] Initialized for {len(cve_list)} CVEs:\033[0m")
    for cve in cve_list:
        print(f"  - {cve}")
    print(f"\033[1;32m[Loop Runner All] Total loop iterations: {iterations}\033[0m")
    print(f"\033[1;32m[Loop Runner All] Trials per CVE: {trials}\033[0m")
    
    python_bin = sys.executable
    manage_py = os.path.join(root_dir, "manage.py")
    manage_script = os.path.join(root_dir, "manage_slurm.py" if args.slurm else "manage.py")
    
    for idx, cve in enumerate(cve_list, 1):
        cve_bench_dir = os.path.join(root_dir, "bench", cve)
        if not os.path.isdir(cve_bench_dir):
            print(f"\n\033[1;31m[Warning] Benchmark directory '{cve_bench_dir}' does not exist. Skipping {cve}.\033[0m")
            continue
            
        cve_duration = 43200
        
        print(f"\033[1;32m[Loop Runner All] Using duration for {cve}: {cve_duration} seconds\033[0m")
            
        print(f"\n\033[1;34m==================================================\033[0m")
        print(f"\033[1;34m[CVE {idx}/{len(cve_list)}] Starting M={iterations} iterations for: {cve}\033[0m")
        print(f"\033[1;34m==================================================\033[0m")
        
        for iteration in range(1, iterations + 1):
            cve_now_str = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"\n\033[1;35m--- [Iteration {iteration}/{iterations}] Running CVE: {cve} (Time: {cve_now_str}) ---\033[0m")
            
            # Step A: Compile docker images
            print("\n\033[1;33m[Step 1/5] Compiling docker images...\033[0m")
            subprocess.run([python_bin, manage_script, "build", cve, str(trials)])

            # Step B: Start containers
            print("\n\033[1;33m[Step 2/5] Starting containers...\033[0m")
            subprocess.run([python_bin, manage_script, "up", cve, str(trials), "-y"])
            
            # Step C: Wait for the duration with tiered success rate checks
            tiers = [300, 600, 900, 1800, 3600, 7200, 10800, 14400, 18000, 21600, 25200, 28800, 32400, 36000, 39600, 43200]
            
            print(f"\n\033[1;33m[Step 3/5] Fuzzing with dynamic tiers {tiers} (up to {cve_duration}s)...\033[0m")
            
            elapsed = 0
            for tier_limit in tiers:
                sleep_time_for_tier = tier_limit - elapsed
                if sleep_time_for_tier <= 0:
                    continue
                    
                print(f"  -> Monitoring fuzzers for {sleep_time_for_tier} seconds to reach next tier ({tier_limit}s)...")
                
                sub_elapsed = 0
                sub_interval = 300
                if sleep_time_for_tier < 60:
                    sub_interval = 10
                elif sleep_time_for_tier < 10:
                    sub_interval = 1
                    
                while sub_elapsed < sleep_time_for_tier:
                    remaining = sleep_time_for_tier - sub_elapsed
                    st = min(remaining, sub_interval)
                    time.sleep(st)
                    sub_elapsed += st
                    # print periodic progress
                    if (elapsed + sub_elapsed) % 300 == 0 or (elapsed + sub_elapsed) == tier_limit:
                        print(f"     -> Elapsed: {elapsed + sub_elapsed}/{cve_duration} seconds...")
                        
                elapsed = tier_limit
                
                # Tier reached! Run sync and check success rate
                print(f"\n\033[1;33m[Tier Evaluation] Reached {elapsed}s. Syncing results and checking success rate...\033[0m")
                
                if args.slurm:
                    # In SLURM mode, compute nodes self-triage and sync results automatically
                    print(f"     -> [SLURM] Reading live triage results from NFS...")
                else:
                    subprocess.run([python_bin, manage_script, "copy", cve, str(trials)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    # Run tte_check locally for non-SLURM
                    subprocess.run([python_bin, manage_py, "tte_check", cve, "-y"])
                
                # Calculate rate
                rate, reached, total = get_latest_success_rate(cve, root_dir)
                print(f"\033[1;32m[Tier Evaluation] Success rate at {elapsed}s: {rate:.1%} ({reached}/{total} trials reached)\033[0m")
                
                if rate >= 0.50:
                    print(f"\033[1;32m[Early Stop] Success rate is {rate:.1%} (>= 50%). Stopping campaign for {cve} early!\033[0m")
                    break
                    
            # Step D: Gracefully stop containers
            print("\n\033[1;33m[Step 4/6] Stopping containers gracefully to flush final state...\033[0m" if not args.slurm else "\n\033[1;33m[Step 4/6] Stopping Slurm jobs...\033[0m")
            subprocess.run([python_bin, manage_script, "stop", cve, str(trials)])
            
            if not args.slurm:
                # Step E: Copy results
                print("\n\033[1;33m[Step 5/6] Copying trial results...\033[0m")
                subprocess.run([python_bin, manage_script, "copy", cve, str(trials)])
                
                # Step F: Shut down containers (clean all containers & volumes)
                print("\n\033[1;33m[Step 6/6] Cleaning up containers and volumes...\033[0m")
                subprocess.run([python_bin, manage_script, "clean"])
            
            # Extra: Run TTE check
            print("\n\033[1;35m[Post-processing] Running TTE check...\033[0m")
            subprocess.run([python_bin, manage_py, "tte_check", cve, "-y"])
            
            print(f"\n\033[1;32m[CVE {cve}] Iteration {iteration}/{iterations} completed. Resting 5 seconds...\033[0m")
            time.sleep(5)
            
        # Post-processing after M iterations for this CVE
        print(f"\n\033[1;35m[Post-processing] Running stat_plot for {cve}...\033[0m")
        subprocess.run([python_bin, manage_py, "stat_plot", cve, "-y"])
        
        print(f"\n\033[1;35m[Post-processing] Running tte_plot for {cve}...\033[0m")
        subprocess.run([python_bin, manage_py, "tte_plot", cve])

        print(f"\n\033[1;35m[Post-processing] Running arm_plot for {cve}...\033[0m")
        subprocess.run([python_bin, manage_py, "arm_plot", cve])
        
        print(f"\n\033[1;32m[CVE {cve}] All {iterations} iterations completed.\033[0m")
        if idx < len(cve_list):
            print("\033[1;32mResting 10 seconds before starting next CVE...\033[0m")
            time.sleep(10)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import sys
import os
import subprocess
import time
import datetime
import argparse

def main():
    root_dir = os.path.abspath(os.path.dirname(__file__))
    
    # Automatically re-execute within the virtualenv if it exists and we're not inside it
    venv_python = os.path.abspath(os.path.join(root_dir, "../.venv/bin/python3"))
    if os.path.isfile(venv_python) and os.path.abspath(sys.executable) != venv_python:
        os.execv(venv_python, [venv_python] + sys.argv)
        
    parser = argparse.ArgumentParser(description="Continuous Trial Runner Loop for All CVEs")
    parser.add_argument("duration", type=int, help="Duration of fuzzing per CVE trial in seconds")
    parser.add_argument("iterations", type=int, help="Number of iterations to run the full CVE loop")
    parser.add_argument("--trials", type=int, default=15, help="Number of trials per CVE (default: 15)")
    args = parser.parse_args()
    
    duration = args.duration
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
    print(f"\033[1;32m[Loop Runner All] Run duration per CVE trial: {duration} seconds\033[0m")
    print(f"\033[1;32m[Loop Runner All] Total loop iterations: {iterations}\033[0m")
    print(f"\033[1;32m[Loop Runner All] Trials per CVE: {trials}\033[0m")
    
    python_bin = sys.executable
    manage_py = os.path.join(root_dir, "manage.py")
    
    for idx, cve in enumerate(cve_list, 1):
        cve_bench_dir = os.path.join(root_dir, "bench", cve)
        if not os.path.isdir(cve_bench_dir):
            print(f"\n\033[1;31m[Warning] Benchmark directory '{cve_bench_dir}' does not exist. Skipping {cve}.\033[0m")
            continue
            
        print(f"\n\033[1;34m==================================================\033[0m")
        print(f"\033[1;34m[CVE {idx}/{len(cve_list)}] Starting M={iterations} iterations for: {cve}\033[0m")
        print(f"\033[1;34m==================================================\033[0m")
        
        for iteration in range(1, iterations + 1):
            cve_now_str = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"\n\033[1;35m--- [Iteration {iteration}/{iterations}] Running CVE: {cve} (Time: {cve_now_str}) ---\033[0m")
            
            # Step A: Start containers
            print("\n\033[1;33m[Step 1/4] Starting containers...\033[0m")
            subprocess.run([python_bin, manage_py, "up", cve, str(trials), "-y"])
            
            # Step B: Wait for the duration
            print(f"\n\033[1;33m[Step 2/4] Fuzzing for {duration} seconds...\033[0m")
            sleep_interval = 300
            if duration < 60:
                sleep_interval = 10
            if duration < 10:
                sleep_interval = 1
                
            elapsed = 0
            while elapsed < duration:
                remaining = duration - elapsed
                sleep_time = min(remaining, sleep_interval)
                time.sleep(sleep_time)
                elapsed += sleep_time
                if elapsed < duration:
                    print(f"  -> Elapsed: {elapsed}/{duration} seconds...")
                    
            # Step C: Copy results
            print("\n\033[1;33m[Step 3/4] Copying trial results...\033[0m")
            subprocess.run([python_bin, manage_py, "copy", cve, str(trials)])
            
            # Step D: Shut down containers (clean all containers & volumes)
            print("\n\033[1;33m[Step 4/4] Cleaning up containers and volumes...\033[0m")
            subprocess.run([python_bin, manage_py, "clean"])
            
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
        
        print(f"\n\033[1;32m[CVE {cve}] All {iterations} iterations completed.\033[0m")
        if idx < len(cve_list):
            print("\033[1;32mResting 10 seconds before starting next CVE...\033[0m")
            time.sleep(10)

if __name__ == "__main__":
    main()

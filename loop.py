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
        
    parser = argparse.ArgumentParser(description="Continuous Trial Runner Loop")
    parser.add_argument("duration", type=int, help="Duration of fuzzing per trial in seconds")
    parser.add_argument("cve", help="CVE identifier")
    parser.add_argument("iterations", type=int, nargs="?", default=1, help="Number of iterations to run the loop (default: 1)")
    parser.add_argument("--trials", type=int, default=15, help="Number of trials per CVE (default: 15)")
    args = parser.parse_args()
    
    duration = args.duration
    cve = args.cve
    iterations = args.iterations
    trials = args.trials
    
    cve_bench_dir = os.path.join(root_dir, "bench", cve)
    if not os.path.isdir(cve_bench_dir):
        print(f"Error: Benchmark directory '{cve_bench_dir}' does not exist.")
        sys.exit(1)
        
    print(f"\033[1;32m[Loop Runner] Initialized for CVE: {cve}\033[0m")
    print(f"\033[1;32m[Loop Runner] Run duration per trial: {duration} seconds\033[0m")
    print(f"\033[1;32m[Loop Runner] Total loop iterations: {iterations}\033[0m")
    print(f"\033[1;32m[Loop Runner] Trials per CVE: {trials}\033[0m")
    
    python_bin = sys.executable
    manage_py = os.path.join(root_dir, "manage.py")
    
    for iteration in range(1, iterations + 1):
        cve_now_str = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"\n\033[1;34m==================================================\033[0m")
        print(f"\033[1;34m[Iteration {iteration}/{iterations}] Running CVE: {cve} (Time: {cve_now_str})\033[0m")
        print(f"\033[1;34m==================================================\033[0m")
        
        # Step A: Compile docker images
        print("\n\033[1;33m[Step 1/5] Compiling docker images...\033[0m")
        subprocess.run([python_bin, manage_py, "build", cve, str(trials)])

        # Step B: Start containers
        print("\n\033[1;33m[Step 2/5] Starting containers...\033[0m")
        subprocess.run([python_bin, manage_py, "up", cve, str(trials), "-y"])
        
        # Step C: Wait for the duration
        print(f"\n\033[1;33m[Step 3/5] Fuzzing for {duration} seconds...\033[0m")
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
                
        # Step D: Copy results
        print("\n\033[1;33m[Step 4/5] Copying trial results...\033[0m")
        subprocess.run([python_bin, manage_py, "copy", cve, str(trials)])
        
        # Step E: Shut down containers (clean all containers & volumes)
        print("\n\033[1;33m[Step 5/5] Cleaning up containers and volumes...\033[0m")
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

if __name__ == "__main__":
    main()

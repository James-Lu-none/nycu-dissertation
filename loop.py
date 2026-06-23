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
    args = parser.parse_args()
    
    duration = args.duration
    cve = args.cve
    
    cve_bench_dir = os.path.join(root_dir, "bench", cve)
    if not os.path.isdir(cve_bench_dir):
        print(f"Error: Benchmark directory '{cve_bench_dir}' does not exist.")
        sys.exit(1)
        
    print(f"\033[1;32m[Loop Runner] Initialized for CVE: {cve}\033[0m")
    print(f"\033[1;32m[Loop Runner] Run duration per trial: {duration} seconds\033[0m")
    
    python_bin = sys.executable
    manage_py = os.path.join(root_dir, "manage.py")
    
    iteration = 1
    while True:
        now_str = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")
        print(f"\n\033[1;34m==================================================\033[0m")
        print(f"\033[1;34m[Iteration {iteration}] Start Time: {now_str}\033[0m")
        print(f"\033[1;34m==================================================\033[0m")
        
        # Step A: Start containers
        print("\n\033[1;33m[Step 1/4] Starting containers...\033[0m")
        subprocess.run([python_bin, manage_py, "up", cve, "15", "-y"])
        
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
        subprocess.run([python_bin, manage_py, "copy", cve])
        
        # Step D: Shut down containers
        print("\n\033[1;33m[Step 4/4] Stopping containers and removing volumes...\033[0m")
        subprocess.run([python_bin, manage_py, "down", cve, "-y"])
        
        # Extra: Run TTE check
        print("\n\033[1;35m[Post-processing] Running TTE check...\033[0m")
        subprocess.run([python_bin, manage_py, "tte_check", cve, "-y"])
        
        print(f"\n\033[1;32m[Iteration {iteration}] Completed. Resting 5 seconds before next iteration...\033[0m")
        time.sleep(5)
        iteration += 1

if __name__ == "__main__":
    main()

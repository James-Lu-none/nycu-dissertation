#!/usr/bin/env python3
import sys
import os
import subprocess
import time
import datetime
import argparse

def get_cve_durations(root_dir):
    durations = {}
    cves_path = os.path.join(root_dir, "cves.env")
    cves_template_path = os.path.join(root_dir, "cves.env.template")
    
    def parse_durations(path):
        d = {}
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ',' in line:
                    parts = line.split(',', 1)
                    cve = parts[0].strip().replace('"', '').replace("'", '').replace(" ", "").replace("\r", "")
                    try:
                        dur = int(parts[1].strip())
                        d[cve] = dur
                    except ValueError:
                        pass
        return d

    if os.path.isfile(cves_path):
        durations = parse_durations(cves_path)
    elif os.path.isfile(cves_template_path):
        durations = parse_durations(cves_template_path)
    return durations

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
        
    # Load CVE durations from cves.env
    cve_durations = get_cve_durations(root_dir)
    
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
            
        cve_duration = cve_durations.get(cve)
        if not cve_duration:
            print(f"\n\033[1;31m[Error] No duration specified for CVE '{cve}' in cves.env. Skipping.\033[0m")
            continue
            
        print(f"\033[1;32m[Loop Runner All] Using duration for {cve}: {cve_duration} seconds (from cves.env)\033[0m")
            
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
            
            # Step C: Wait for the duration
            print(f"\n\033[1;33m[Step 3/5] Fuzzing for {cve_duration} seconds...\033[0m")
            sleep_interval = 300
            if cve_duration < 60:
                sleep_interval = 10
            if cve_duration < 10:
                sleep_interval = 1
                
            elapsed = 0
            while elapsed < cve_duration:
                remaining = cve_duration - elapsed
                sleep_time = min(remaining, sleep_interval)
                time.sleep(sleep_time)
                elapsed += sleep_time
                if elapsed < cve_duration:
                    print(f"  -> Elapsed: {elapsed}/{cve_duration} seconds...")
                    
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

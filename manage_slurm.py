#!/usr/bin/env python3
import sys
import os
import subprocess
import datetime
import time

# Import shared functions from manage.py
import manage

def get_env_dict(cve_bench_dir):
    env_dict = {}
    env_file = os.path.join(cve_bench_dir, ".env")
    if os.path.isfile(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        k, v = line.split('=', 1)
                        env_dict[k.strip()] = v.strip().strip('"').strip("'")
    return env_dict

def run_slurm_command(root_dir, command, cve_list, num_trials, run_all, yes, extra_args, trial_name_arg=None):
    for cve in cve_list:
        cve_bench_dir = os.path.join(root_dir, "bench", cve)
        if not os.path.isdir(cve_bench_dir):
            print(f"Warning: Benchmark directory 'bench/{cve}' not found. Skipping.")
            continue
            
        current_session_file = os.path.join(cve_bench_dir, ".current_session")
        env_dict = get_env_dict(cve_bench_dir)
        
        if command == "up":
            active_trial_name = trial_name_arg if trial_name_arg else f"trial_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            active_session_id = f"session_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            os.makedirs(cve_bench_dir, exist_ok=True)
            with open(current_session_file, "w") as f:
                f.write(f"SESSION_ID={active_session_id}\n")
                f.write(f"TRIAL_NAME={active_trial_name}\n")
                
            session_id = active_session_id
            trial_name = active_trial_name
            print(f"Starting Slurm jobs for \033[1;35m{cve}\033[0m with SESSION_ID=\033[1;36m{session_id}\033[0m and TRIAL_NAME=\033[1;35m{trial_name}\033[0m")
            
            if run_all:
                num_tasks = num_trials * 4
                run_all_val = "1"
            else:
                num_tasks = num_trials * 2
                run_all_val = "0"
            
            sbatch_cmd = [
                "sbatch",
                f"--job-name=afl_{cve}",
                f"--array=1-{num_tasks}",
                f"--export=ALL,CVE={cve},SESSION_ID={session_id},TRIAL_NAME={trial_name},RUN_ALL={run_all_val}"
            ]
            
            # Export variables from .env
            for k, v in env_dict.items():
                sbatch_cmd[-1] += f",{k}={v}"
                
            sbatch_cmd.append(os.path.join(root_dir, "scripts/sbatch.sh"))
            print(f"Executing: {' '.join(sbatch_cmd)}")
            subprocess.run(sbatch_cmd)
            
        elif command == "down":
            print(f"Stopping Slurm jobs for \033[1;35m{cve}\033[0m")
            subprocess.run(["scancel", f"--name=afl_{cve}"])
            
        elif command == "build":
            print(f"\n\033[1;34m[Build Fuzzer (Slurm/Apptainer)]\033[0m \033[1;35m{cve}\033[0m")
            image_name = env_dict.get("IMAGE_NAME")
            if not image_name:
                if cve in ["cafl", "dafl"]:
                    image_name = f"{cve}:latest"
                else:
                    print(f"Error: IMAGE_NAME not found in bench/{cve}/.env")
                    continue
                
            sif_name = f"{image_name}.sif"
            sif_path = os.path.join(cve_bench_dir, sif_name)
            
            if os.path.exists(sif_path):
                os.remove(sif_path)
            
            print(f"Pulling Apptainer image for {image_name}...")
            docker_uri = f"docker://registry.optixbase.com:30000/{image_name}"
            apptainer_cmd = ["apptainer", "pull", sif_path, docker_uri]
            
            apptainer_res = subprocess.run(apptainer_cmd, cwd=cve_bench_dir)
            if apptainer_res.returncode == 0:
                print(f"\033[1;32mSuccessfully pulled Apptainer image: {sif_path}\033[0m")
            else:
                print(f"\033[1;31mFailed to pull Apptainer image: {sif_path}\033[0m")

def run_slurm_status(root_dir, cve_list):
    for cve in cve_list:
        print(f"\n\033[1;34m[Slurm Status]\033[0m \033[1;35m{cve}\033[0m")
        res = subprocess.run(["squeue", "-n", f"afl_{cve}"], capture_output=True, text=True)
        print(res.stdout)
        
        active_trial = manage.get_active_trial_name(root_dir, cve)
        print(f"Active Trial Folder (synced): \033[1;35m{active_trial}\033[0m")
        print("Note: Stats are syncing in the background from local compute nodes.")

def run_slurm_copy(root_dir, cve_list, num_trials, trial_name_arg):
    print("\n\033[1;34m[Slurm Copy Request]\033[0m")
    import glob
    for cve in cve_list:
        trial_name = trial_name_arg if trial_name_arg else manage.get_active_trial_name(root_dir, cve)
        if not trial_name:
            continue
        
        print(f"Requesting background sync for \033[1;35m{cve}\033[0m (trial: {trial_name})...")
        pattern = os.path.join(root_dir, "artifact", cve, trial_name, "*", "trial*")
        dirs = glob.glob(pattern)
        for d in dirs:
            if os.path.isdir(d):
                with open(os.path.join(d, ".pull_request"), "w") as f:
                    f.write("sync")

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    command, target_cve, num_trials, trial_name_arg, run_all, yes, extra_args = manage.parse_arguments(root_dir)
    
    if command is None:
        manage.print_usage()
        sys.exit(1)
        
    cve_list = []
    if target_cve:
        cve_list.append(target_cve)
    else:
        sel_cve = manage.select_cve_interactively(root_dir, command, yes)
        if sel_cve:
            cve_list.append(sel_cve)
        else:
            sys.exit(0)
            
    if num_trials is None and command in ["up", "down", "copy"]:
        try:
            num_trials = manage.detect_num_trials(root_dir, cve_list)
        except Exception:
            num_trials = 5
        if num_trials is None:
            num_trials = 5
            
    if command in ["up", "down", "build"]:
        run_slurm_command(root_dir, command, cve_list, num_trials, run_all, yes, extra_args, trial_name_arg)
    elif command == "stop":
        run_slurm_command(root_dir, "down", cve_list, num_trials, run_all, yes, extra_args, trial_name_arg)
    elif command == "status":
        run_slurm_status(root_dir, cve_list)
    elif command == "copy":
        run_slurm_copy(root_dir, cve_list, num_trials, trial_name_arg)
    elif command in ["stat_plot", "tte_check", "tte_plot", "ttr", "arm_plot", "summary"]:
        # Fallback to manage.py implementations
        if command == "stat_plot":
            manage.run_stat_plot(root_dir, cve_list, trial_name_arg, yes)
        elif command == "tte_check":
            manage.run_tte_check(root_dir, cve_list, trial_name_arg, yes)
        elif command == "tte_plot":
            manage.run_tte_plot(root_dir, cve_list, trial_name_arg)
        elif command == "ttr":
            manage.run_ttr(root_dir, cve_list, num_trials, trial_name_arg)
        elif command == "arm_plot":
            manage.run_arm_plot(root_dir, cve_list, trial_name_arg)

if __name__ == "__main__":
    main()

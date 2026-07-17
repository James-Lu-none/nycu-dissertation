#!/usr/bin/env python3
import sys
import os
import subprocess
import re
import datetime
import shutil
import time
import concurrent.futures

def get_cves(root_dir):
    cves_path = os.path.join(root_dir, "cves.env")
    cves_template_path = os.path.join(root_dir, "cves.env.template")
    cves = []
    
    def parse_file(path):
        results = []
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ',' in line:
                    line = line.split(',', 1)[0].strip()
                cve = line.replace('"', '').replace("'", '').replace(" ", "").replace("\r", "")
                if cve:
                    results.append(cve)
        return results

    if os.path.isfile(cves_path):
        cves = parse_file(cves_path)
    elif os.path.isfile(cves_template_path):
        cves = parse_file(cves_template_path)
    else:
        # Fallback to directories under bench/ containing .env
        bench_dir = os.path.join(root_dir, "bench")
        if os.path.isdir(bench_dir):
            for item in os.listdir(bench_dir):
                item_path = os.path.join(bench_dir, item)
                if os.path.isdir(item_path) and os.path.isfile(os.path.join(item_path, ".env")):
                    cves.append(item)
    return cves

def is_cve(root_dir, arg):
    active_cves = get_cves(root_dir)
    if arg in active_cves:
        return True
    if os.path.isdir(os.path.join(root_dir, "bench", arg)):
        return True
    return False

def get_active_trial_name(root_dir, cve):
    container_name = f"{cve}-afl-base-1"
    try:
        res = subprocess.run(["docker", "ps", "-a", "-q", "-f", f"name=^/{container_name}$"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            inspect_res = subprocess.run(["docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", container_name], capture_output=True, text=True)
            if inspect_res.returncode == 0:
                for line in inspect_res.stdout.splitlines():
                    if line.startswith("TRIAL_NAME="):
                        return line.split("=", 1)[1].strip()
    except Exception:
        pass

    curr_session_path = os.path.join(root_dir, "bench", cve, ".current_session")
    if os.path.isfile(curr_session_path):
        try:
            with open(curr_session_path, 'r') as f:
                for line in f:
                    if line.startswith("TRIAL_NAME="):
                        return line.split("=", 1)[1].strip()
        except Exception:
            pass

    artifact_cve_dir = os.path.join(root_dir, "artifact", cve)
    if os.path.isdir(artifact_cve_dir):
        try:
            candidates = []
            for item in os.listdir(artifact_cve_dir):
                item_path = os.path.join(artifact_cve_dir, item)
                if os.path.isdir(item_path) and item not in ["plot", "TTE_check"]:
                    mtime = os.path.getmtime(item_path)
                    candidates.append((mtime, item))
            if candidates:
                candidates.sort()
                latest_dir = candidates[-1][1]
                normalized = re.sub(r'_\d{8}_\d{6}$', '', latest_dir)
                normalized = re.sub(r'_\d{8}_\d{6}_trial\d+$', '', normalized)
                normalized = re.sub(r'_trial\d+$', '', normalized)
                return normalized
        except Exception:
            pass

    return "trial_default"

def print_usage():
    print("Usage: python3 manage.py {up|down|stop|build|status|log|clean|copy|stat_plot|tte_check|tte_plot|ttr|arm_plot|summary} [cve_name|dafl|cafl|muoafl] [trials] [trial_name] [--all] [-y] [--tag tag_name] [--registry registry_url]")
    print("\nCommands:")
    print("  up        : Start docker containers for CVE trials")
    print("  down      : Stop docker containers and remove named volumes (-v)")
    print("  stop      : Gracefully stop docker containers with SIGINT")
    print("  build     : Build docker images for CVE trials, or build fuzzer base images (dafl|cafl)")
    print("  status    : Check if fuzzer process is active inside containers")
    print("  log       : Print /workspace/cpu_binding.log from inside containers")
    print("  clean     : Force stop and remove containers, volumes, and images")
    print("  copy      : Copy stats from docker containers (excluding .cur_input)")
    print("  stat_plot : Run stat_plot.py on active CVEs (plots already copied stats)")
    print("  tte_check : Run TTE_check.py on active CVEs")
    print("  tte_plot  : Run TTE_plot.py on active CVEs")
    print("  ttr       : Run TTR.py on active CVEs (copies TTR logs/stats and plots)")
    print("  arm_plot  : Run ARM_plot.py on active CVEs (visualizes ARM rules)")
    print("  summary   : Aggregate TTE dd_dual summary tables and DGF compile info across benchmarks")

def build_fuzzer_image(root_dir, target, tag_value, registry_value, extra_args=None):
    if extra_args is None:
        extra_args = []
    afl_dir = os.path.join(root_dir, "AFLplusplus")
    if not os.path.isdir(afl_dir):
        print(f"Error: AFLplusplus directory not found at {afl_dir}")
        sys.exit(1)
        
    checkout_branch = f"{target}-v1" if target in ["dafl", "cafl"] else f"{target}-{tag_value}"
        
    print(f"\n\033[1;34m[Build Fuzzer]\033[0m Checking out git branch \033[1;35m{checkout_branch}\033[0m in AFLplusplus...")
    res = subprocess.run(["git", "checkout", checkout_branch], cwd=afl_dir)
    if res.returncode != 0:
        print(f"Error: Failed to checkout branch '{checkout_branch}' in {afl_dir}")
        sys.exit(1)
        
    actual_tag = "v1" if target in ["dafl", "cafl"] else tag_value
    image_tag = f"{target}:{actual_tag}"
    registry_tag = f"{registry_value}/{target}:{actual_tag}"
    print(f"\n\033[1;34m[Build Docker]\033[0m Building docker image \033[1;35m{image_tag}\033[0m and \033[1;35m{registry_tag}\033[0m...")
    
    cmd = ["docker", "build"]
    if target == "cafl":
        cmd += ["--build-arg", "CPPFLAGS=-Dcd"]
    if extra_args:
        cmd += extra_args
    cmd += ["-t", image_tag, "-t", registry_tag, "./AFLplusplus"]
    
    print(f"Executing: {' '.join(cmd)}")
    build_res = subprocess.run(cmd, cwd=root_dir)
    if build_res.returncode != 0:
        print(f"Error: Failed to build docker image {image_tag}")
        sys.exit(1)
        
    print(f"\n\033[1;34m[Docker Push]\033[0m Pushing image \033[1;35m{registry_tag}\033[0m to registry...")
    push_res = subprocess.run(["docker", "push", registry_tag])
    if push_res.returncode != 0:
        print(f"Error: Failed to push docker image {registry_tag}")
        sys.exit(1)
        
    print(f"\n\033[1;32mSuccessfully built and pushed {registry_tag}\033[0m")

def parse_arguments(root_dir):
    args = sys.argv[1:]
    
    command = None
    target_cve = None
    num_trials = None
    trial_name = None
    run_all = False
    yes = False
    registry_value = "registry.optixbase.com:30000"
    tags_value = None
    only_crashes = False
    extra_args = []
    
    valid_commands = ["up", "down", "stop", "build", "status", "log", "clean", "copy", "stat_plot", "tte_check", "tte_plot", "ttr", "arm_plot", "summary"]
    
    i = 0
    while i < len(args):
        arg = args[i]
        arg_lower = arg.lower()
        if arg == "--tags" and i + 1 < len(args):
            tags_value = args[i+1]
            i += 2
            continue
        if arg == "--registry" and i + 1 < len(args):
            registry_value = args[i+1]
            i += 2
            continue

        if arg_lower == "--all":
            run_all = True
        elif arg_lower in ["-y", "--yes", "--non-interactive"]:
            yes = True
        elif arg_lower in ["-h", "--help"]:
            print_usage()
            sys.exit(0)
        elif arg_lower == "--only-crashes":
            only_crashes = True
        elif arg.startswith("-"):
            extra_args.append(arg)
        elif command is None and arg_lower in valid_commands:
            command = arg_lower
        elif arg.isdigit():
            num_trials = int(arg)
        elif is_cve(root_dir, arg):
            target_cve = arg
        elif arg_lower in ["dafl", "cafl", "muoafl"]:
            target_cve = arg_lower
        else:
            trial_name = arg
            
        i += 1
            
    return command, target_cve, num_trials, trial_name, run_all, yes, tags_value, registry_value, only_crashes, extra_args

def select_cve_interactively(root_dir, action, yes):
    all_cves = get_cves(root_dir)
    if not all_cves:
        print(f"No active CVEs found to {action}.")
        return None
        
    if yes:
        return all_cves[0]
        
    print("CVE list:")
    for idx, cve in enumerate(all_cves):
        print(f"{idx+1}. {cve}")
        
    try:
        selection = input(f"Select a CVE to {action} (1-{len(all_cves)}): ").strip()
        sel_idx = int(selection) - 1
        if 0 <= sel_idx < len(all_cves):
            selected_cve = all_cves[sel_idx]
            
            if action == "down":
                print(f"\nSelected CVE: \033[1;33m{selected_cve}\033[0m")
                confirm = input(f"Are you sure you want to stop and remove volumes for {selected_cve}? (y/N): ").strip().lower()
                if confirm != 'y':
                    print("Aborted.")
                    return None
            return selected_cve
        else:
            print("Error: Invalid selection.")
            return None
    except (ValueError, IndexError, KeyboardInterrupt):
        print("\nAborted.")
        return None

def run_clean():
    print("\n\033[1;31m[Docker-Prune] Stopping and removing all containers & pruning volumes...\033[0m")
    res = subprocess.run(["docker", "ps", "-aq"], capture_output=True, text=True)
    container_ids = res.stdout.strip().split()
    if container_ids:
        print("Stopping all containers...")
        subprocess.run(["docker", "stop"] + container_ids, stderr=subprocess.DEVNULL)
        print("Removing all containers...")
        subprocess.run(["docker", "rm"] + container_ids, stderr=subprocess.DEVNULL)
    else:
        print("No containers to stop/remove.")
    print("Pruning all unused volumes...")
    subprocess.run(["docker", "volume", "prune", "-a", "-f"])

    print("Pruning all unused networks...")
    subprocess.run(["docker", "network", "prune", "-f"])

    print("\n\033[1;34m[Docker Volumes]\033[0m")
    subprocess.run(["docker", "volume", "ls"])
    
    print("\n\033[1;34m[Docker Networks]\033[0m")
    subprocess.run(["docker", "network", "ls"])
    
    print("\n\033[1;34m[Docker Containers]\033[0m")
    subprocess.run(["docker", "ps", "-a"])
    print("\n\033[1;32mDone.\033[0m")

def run_docker_compose_command(root_dir, command, cve_list, num_trials, run_all, yes, tags_value, registry_value, extra_args, trial_name_arg=None):
    python_bin = sys.executable
    tags_list = [t.strip() for t in (tags_value or "v1").split(",") if t.strip()]
    if not tags_list:
        tags_list = ["v1"]
    gen_cmd = [python_bin, os.path.join(root_dir, "scripts/generate_master_compose.py"), str(num_trials), "--tags", ",".join(tags_list)]
    subprocess.run(gen_cmd)
    
    def process_cve(cve):
        print(f"\n\033[1;34m[Docker-Compose]\033[0m \033[1;35m{cve}\033[0m >> \033[1;32m{command} {' '.join(extra_args)}\033[0m")
        
        cve_bench_dir = os.path.join(root_dir, "bench", cve)
        if not os.path.isdir(cve_bench_dir):
            print(f"Warning: Benchmark directory 'bench/{cve}' not found. Skipping.")
            return
            
        current_session_file = os.path.join(cve_bench_dir, ".current_session")
        env_dict = os.environ.copy()
        
        if command == "up":
            active_trial_name = trial_name_arg if trial_name_arg else f"trial_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            active_session_id = f"session_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            os.makedirs(cve_bench_dir, exist_ok=True)
            with open(current_session_file, "w") as f:
                f.write(f"SESSION_ID={active_session_id}\n")
                f.write(f"TRIAL_NAME={active_trial_name}\n")
                
            env_dict["SESSION_ID"] = active_session_id
            env_dict["TRIAL_NAME"] = active_trial_name
            print(f"Starting run with SESSION_ID=\033[1;36m{active_session_id}\033[0m and TRIAL_NAME=\033[1;35m{active_trial_name}\033[0m")
        else:
            session_id = "dummy_session"
            trial_name = "dummy_trial"
            if os.path.isfile(current_session_file):
                with open(current_session_file, 'r') as f:
                    for line in f:
                        if line.startswith("SESSION_ID="):
                            session_id = line.split("=", 1)[1].strip()
                        elif line.startswith("TRIAL_NAME="):
                            trial_name = line.split("=", 1)[1].strip()
            env_dict["SESSION_ID"] = session_id
            env_dict["TRIAL_NAME"] = trial_name
            
        # Read IMAGE_NAME from .env and update dynamically
        env_file = os.path.join(cve_bench_dir, ".env")
        parsed_image_name = None
        if os.path.isfile(env_file):
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        k, v = line.split('=', 1)
                        if k.strip() == "IMAGE_NAME":
                            parsed_image_name = v.strip().strip('"').strip("'")
                            break
                            
        if parsed_image_name:
            if command != "build" and registry_value:
                env_dict["IMAGE_NAME"] = f"{registry_value}/{parsed_image_name}"
            else:
                env_dict["IMAGE_NAME"] = parsed_image_name
        
        env_dict["MUOAFL_TAGS"] = tags_value if tags_value is not None else ""
        env_dict["REGISTRY"] = registry_value
            
        compose_yaml_path = os.path.join(cve_bench_dir, "compose.yaml")
        if not os.path.isfile(compose_yaml_path):
            print(f"Warning: compose.yaml not found in bench/{cve}. Skipping.")
            return
            
        cmd_args = ["docker", "compose"]
        if command == "up":
            cmd_args += ["up", "-d", "--build", "--pull", "always"] + extra_args
            services = []
            for i in range(1, num_trials + 1):
                if run_all:
                    services += [f"afl-base-{i}", f"afl-cd-{i}"]
                services += [f"afl-dd-{i}"]
                for t in tags_list:
                    services += [f"afl-muoafl-{t}-{i}"]
            cmd_args += services
        elif command == "down":
            cmd_args += ["down"]
            if not extra_args:
                cmd_args.append("-v")
            else:
                cmd_args += extra_args
        elif command == "build":
            cmd_args += ["build", "--pull"] + extra_args
            
        build_res = subprocess.run(cmd_args, cwd=cve_bench_dir, env=env_dict)
        if command == "build" and build_res.returncode == 0:
            image_name = env_dict.get("IMAGE_NAME")
            if not image_name and parsed_image_name:
                image_name = parsed_image_name
            if image_name:
                registry_tag = f"{registry_value}/{image_name}"
                print(f"\n\033[1;34m[Docker Tag & Push]\033[0m Tagging \033[1;35m{image_name}\033[0m as \033[1;35m{registry_tag}\033[0m...")
                tag_res = subprocess.run(["docker", "tag", image_name, registry_tag])
                if tag_res.returncode == 0:
                    print(f"\033[1;34m[Docker Tag & Push]\033[0m Pushing \033[1;35m{registry_tag}\033[0m to registry...")
                    push_res = subprocess.run(["docker", "push", registry_tag])
                    if push_res.returncode != 0:
                        print(f"\033[1;31mError: Failed to push docker image {registry_tag}\033[0m")
                else:
                    print(f"\033[1;31mError: Failed to tag docker image {image_name} as {registry_tag}\033[0m")
            else:
                print(f"\033[1;31mError: IMAGE_NAME not found in {env_file}\033[0m")

    if command == "build":
        system_cores = os.cpu_count() or 4
        # Calculate max_workers using system cores. We limit it to avoid OOM, e.g. using all cores.
        max_workers = min(len(cve_list), system_cores, 16)
        print(f"\n\033[1;34m[Parallel Build]\033[0m Compiling {len(cve_list)} CVE images in parallel with max_workers={max_workers} (Detected Cores: {system_cores})...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            try:
                for _ in executor.map(process_cve, cve_list):
                    pass
            except Exception as e:
                print(f"Error during parallel build: {e}")
    else:
        for cve in cve_list:
            process_cve(cve)
            
    print("\n\033[1;32mDone.\033[0m")

def run_stop(cve_list):
    for cve in cve_list:
        print(f"\n\033[1;34m[Fuzzer Stop]\033[0m \033[1;35m{cve}\033[0m")
        # Since fuzzer processes are run as root inside the container, we can send SIGINT using 
        # docker exec without requiring sudo on the host.
        res = subprocess.run(["docker", "ps", "--filter", f"name=^{cve}-afl-", "--format", "{{.Names}}"], capture_output=True, text=True)
        containers = [c.strip() for c in res.stdout.strip().splitlines() if c.strip()]
        print("Number of containers to stop is: ", len(containers))
        for c in containers:
            print(f"Stopping fuzzer process inside container {c}...", end="")
            subprocess.run(["docker", "exec", c, "pkill", "-INT", "-f", "afl-fuzz"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("Done.")
        if containers:
            print(f"Stopping fuzzer processes inside containers gracefully for \033[1;35m{cve}\033[0m...")
            time.sleep(3.0)
    print("\n\033[1;32mDone.\033[0m")

def copy_all_txt_files(container_name, target_dir, is_slave=False):
    txt_files = set()
    
    res_exec = subprocess.run(["docker", "exec", container_name, "bash", "-c", "find /workspace -maxdepth 1 -name '*.txt' 2>/dev/null"], capture_output=True, text=True)
    if res_exec.returncode == 0 and res_exec.stdout.strip():
        for line in res_exec.stdout.splitlines():
            line = line.strip()
            if line.endswith(".txt"):
                txt_files.add(os.path.basename(line))
                
    res_diff = subprocess.run(["docker", "diff", container_name], capture_output=True, text=True)
    if res_diff.returncode == 0 and res_diff.stdout.strip():
        for line in res_diff.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                path = parts[1]
                if path.endswith(".txt"):
                    txt_files.add(os.path.basename(path))

    for f_name in txt_files:
        dest_path = os.path.join(target_dir, f_name)
            
        subprocess.run(["docker", "cp", f"{container_name}:/workspace/{f_name}", dest_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_copy(root_dir, cve_list, num_trials, trial_name_arg, only_crashes=False):
    trials = list(range(1, num_trials + 1))
    
    for cve in cve_list:
        # We need to find the session_id and trial_name from any container of this cve
        res = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}", "-f", f"name=^{cve}-afl-"], capture_output=True, text=True)
        containers = [c.strip() for c in res.stdout.splitlines() if c.strip()]
        if not containers:
            print(f"Warning: No containers found for {cve}.")
            continue
            
        # Extract from the first container we find
        container_name = containers[0]
            
        session_id = ""
        trial_name = ""
        
        inspect_res = subprocess.run(["docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", container_name], capture_output=True, text=True)
        if inspect_res.returncode == 0:
            for line in inspect_res.stdout.splitlines():
                if line.startswith("SESSION_ID="):
                    session_id = line.split("=", 1)[1].strip()
                elif line.startswith("TRIAL_NAME="):
                    trial_name = line.split("=", 1)[1].strip()
                        
        if not session_id or not trial_name:
            curr_session_path = os.path.join(root_dir, "bench", cve, ".current_session")
            if os.path.isfile(curr_session_path):
                with open(curr_session_path, 'r') as f:
                    for line in f:
                        if line.startswith("SESSION_ID="):
                            session_id = line.split("=", 1)[1].strip()
                        elif line.startswith("TRIAL_NAME="):
                            trial_name = line.split("=", 1)[1].strip()
                            
        now_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if not trial_name:
            trial_name = f"trial_{now_str}"
        if not session_id:
            session_id = f"session_{now_str}"
            
        artifact_trial_dir = os.path.join(root_dir, "artifact", cve, trial_name)
        if os.path.isdir(artifact_trial_dir):
            exist_session_id = ""
            session_id_file = os.path.join(artifact_trial_dir, ".session_id")
            if os.path.isfile(session_id_file):
                with open(session_id_file, 'r') as f:
                    exist_session_id = f.read().strip()
            if exist_session_id != session_id:
                trial_name = f"{trial_name}_{now_str}"
                artifact_trial_dir = os.path.join(root_dir, "artifact", cve, trial_name)
                
        print(f"Copying results for trial run: \033[1;35m{trial_name}\033[0m")
        os.makedirs(artifact_trial_dir, exist_ok=True)
        with open(os.path.join(artifact_trial_dir, ".session_id"), "w") as f:
            f.write(session_id)
            
        for i in trials:
            # Re-fetch all containers just for this trial `i` and excluding slaves
            res = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}", "-f", f"name=^{cve}-afl-.*-{i}$"], capture_output=True, text=True)
            trial_containers = [c.strip() for c in res.stdout.splitlines() if c.strip() and "-slave-" not in c]
            
            for c_name in trial_containers:
                prefix = f"{cve}-afl-"
                suffix = f"-{i}"
                if c_name.startswith(prefix) and c_name.endswith(suffix):
                    method = c_name[len(prefix):-len(suffix)]
                    
                    target_dir = os.path.join(artifact_trial_dir, method, f"trial{i}")
                    os.makedirs(target_dir, exist_ok=True)
                    print(f"Copying results from {c_name:<55}... ", end="", flush=True)
                    
                    copy_all_txt_files(c_name, target_dir)
                    
                    # Copy from slave if it exists
                    slave_c_name = f"{cve}-afl-{method}-slave-{i}"
                    res_slave = subprocess.run(["docker", "ps", "-a", "-q", "-f", f"name=^/{slave_c_name}$"], capture_output=True, text=True)
                    if res_slave.stdout.strip():
                        copy_all_txt_files(slave_c_name, target_dir)
                        
                    res_run = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", c_name], capture_output=True, text=True)
                    running = res_run.stdout.strip() == "true"
                    
                    success = False
                    if running:
                        tar_cmd = f"docker exec {c_name} tar -cf - -C /workspace out --exclude=.cur_input --exclude=*.pyc --exclude=__pycache__"
                        if only_crashes:
                            tar_cmd += " --exclude=queue --exclude=hangs"
                        try:
                            p1 = subprocess.Popen(tar_cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                            p2 = subprocess.Popen(["tar", "-xf", "-", "-C", target_dir], stdin=p1.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            p1.stdout.close()
                            p2.communicate()
                            success = p2.returncode == 0
                        except Exception:
                            pass
                    else:
                        res_cp = subprocess.run(["docker", "cp", f"{c_name}:/workspace/out", target_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        success = res_cp.returncode == 0
                    
                for root, dirs, files in os.walk(target_dir):
                    for file in files:
                        if file.endswith(".pyc"):
                            try:
                                os.remove(os.path.join(root, file))
                            except Exception:
                                pass
                    for d in list(dirs):
                        if d == "__pycache__":
                            try:
                                shutil.rmtree(os.path.join(root, d))
                            except Exception:
                                pass
                
                size_res = subprocess.run(["du", "-sh", os.path.join(target_dir, "out")], capture_output=True, text=True)
                size = size_res.stdout.strip().split()[0] if size_res.returncode == 0 and size_res.stdout.strip() else ""
                
                if success and size:
                    print(f"\033[1;32mDone\033[0m (size: {size})")
                else:
                    print("\033[1;31mFailed\033[0m")
                    
    print("\n\033[1;32mDone.\033[0m")

def run_status(cve_list):
    for cve in cve_list:
        print(f"\n\033[1;34m[Status]\033[0m \033[1;35m{cve}\033[0m")
        res = subprocess.run(["docker", "ps", "-a", "--filter", f"name=^/{cve}-afl-", "--format", "{{.Names}}"], capture_output=True, text=True)
        containers = sorted(res.stdout.strip().split())
        if not containers:
            print(f"No containers found for {cve}.")
            continue
            
        for container in containers:
            print(f"{container:<55} : ", end="", flush=True)
            res_run = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", container], capture_output=True, text=True)
            is_running = res_run.stdout.strip() == "true"
            if is_running:
                res_env = subprocess.run(["docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", container], capture_output=True, text=True)
                target_bin = ""
                fuzzer_name = "main"
                for line in res_env.stdout.splitlines():
                    if line.startswith("TARGET_BIN="):
                        target_bin = line.split("=", 1)[1].strip()
                    elif line.startswith("FUZZER_NAME="):
                        fuzzer_name = line.split("=", 1)[1].strip()
                
                session_name = os.path.basename(target_bin) if target_bin else ""
                tmux_cmd = f"tmux list-panes -t {session_name} -F '#{{pane_pid}}' 2>/dev/null" if session_name else ""
                fuzzer_pid = ""
                if tmux_cmd:
                    res_pid = subprocess.run(["docker", "exec", container, "bash", "-c", tmux_cmd], capture_output=True, text=True)
                    fuzzer_pid = res_pid.stdout.strip()
                    
                fuzzer_active = False
                core_info = "core: unknown"
                if fuzzer_pid.isdigit():
                    pid = int(fuzzer_pid)
                    status_path = f"/proc/{pid}/status"
                    if os.path.isfile(status_path):
                        try:
                            with open(status_path, 'r') as f:
                                for line in f:
                                    if line.startswith("Cpus_allowed_list:"):
                                        core_info = f"core: {line.split(':', 1)[1].strip()}"
                                        break
                            with open(f"/proc/{pid}/cmdline", 'r') as f:
                                cmdline = f.read().replace('\x00', ' ')
                                if "afl-fuzz" in cmdline:
                                    fuzzer_active = True
                        except Exception:
                            pass
                            
                if fuzzer_active:
                    print(f"\033[1;32mActive ({core_info})\033[0m", end="", flush=True)
                    stats_cmd = f"cat /workspace/out/{fuzzer_name}/fuzzer_stats 2>/dev/null"
                    res_stats = subprocess.run(["docker", "exec", container, "bash", "-c", stats_cmd], capture_output=True, text=True)
                    stats_content = res_stats.stdout.strip()
                    if stats_content:
                        bitmap_cvg = ""
                        saved_crashes = ""
                        corpus_imported = ""
                        last_crash = 0
                        
                        for line in stats_content.splitlines():
                            if line.startswith("bitmap_cvg"):
                                bitmap_cvg = line.split(":", 1)[1].strip()
                            elif line.startswith("saved_crashes"):
                                saved_crashes = line.split(":", 1)[1].strip()
                            elif line.startswith("corpus_imported"):
                                corpus_imported = line.split(":", 1)[1].strip()
                            elif line.startswith("last_crash"):
                                try:
                                    last_crash = int(line.split(":", 1)[1].strip())
                                except ValueError:
                                    pass
                                    
                        last_crash_str = "none"
                        if last_crash > 0:
                            diff = int(time.time()) - last_crash
                            if diff < 0:
                                diff = 0
                            hours = diff // 3600
                            minutes = (diff % 3600) // 60
                            seconds = diff % 60
                            last_crash_str = f"{hours}h {minutes}m {seconds}s ago"
                            
                        print(f" | cvg: \033[1;36m{bitmap_cvg}\033[0m | crashes: \033[1;31m{saved_crashes}\033[0m | imported: \033[1;33m{corpus_imported}\033[0m | last crash: \033[1;35m{last_crash_str}\033[0m")
                    else:
                        print(" | \033[1;30m(No stats available yet)\033[0m")
                else:
                    print("\033[1;31mInactive (Fuzzer process died!)\033[0m")
            else:
                print("\033[1;30mStopped (Container not running)\033[0m")

def run_log(cve_list):
    for cve in cve_list:
        res = subprocess.run(["docker", "ps", "-a", "--filter", f"name=^/{cve}-afl-", "--format", "{{.Names}}"], capture_output=True, text=True)
        containers = sorted(res.stdout.strip().split())
        for container in containers:
            print(f"\n\033[1;36m>>> Logs for {container}:\033[0m")
            subprocess.run(["docker", "exec", container, "cat", "/workspace/cpu_binding.log"])

def select_trial_interactively(root_dir, cve, yes):
    artifact_cve_dir = os.path.join(root_dir, "artifact", cve)
    trials = []
    if os.path.isdir(artifact_cve_dir):
        for item in os.listdir(artifact_cve_dir):
            item_path = os.path.join(artifact_cve_dir, item)
            if os.path.isdir(item_path) and item not in ["plot", "TTE_check"]:
                trials.append(item)
    trials.sort(reverse=True)
    
    if not trials:
        return get_active_trial_name(root_dir, cve)
    elif len(trials) == 1:
        return trials[0]
    else:
        if yes:
            return trials[0]
        
        print(f"\nAvailable trials for \033[1;35m{cve}\033[0m:")
        for idx, t in enumerate(trials):
            print(f"{idx+1}. {t}")
        try:
            selection = input(f"Select a trial (1-{len(trials)}, default 1: {trials[0]}): ").strip()
            if not selection:
                return trials[0]
            else:
                sel_idx = int(selection) - 1
                if 0 <= sel_idx < len(trials):
                    return trials[sel_idx]
                else:
                    print(f"Error: Invalid selection. Using default: {trials[0]}")
                    return trials[0]
        except (ValueError, IndexError, KeyboardInterrupt):
            print(f"Using default: {trials[0]}")
            return trials[0]

def select_cve_and_trial_interactively(root_dir, cve_list):
    options = []
    option_counter = 1
    
    print("\nAvailable trials:")
    for cve in cve_list:
        print(f"\033[1;35m{cve}\033[0m")
        artifact_cve_dir = os.path.join(root_dir, "artifact", cve)
        trials = []
        if os.path.isdir(artifact_cve_dir):
            for item in os.listdir(artifact_cve_dir):
                item_path = os.path.join(artifact_cve_dir, item)
                if os.path.isdir(item_path) and item not in ["plot", "TTE_check"]:
                    trials.append(item)
        trials.sort(reverse=True)
        
        if not trials:
            active_trial = get_active_trial_name(root_dir, cve)
            trials = [active_trial]
            
        for t in trials:
            print(f"  {option_counter}. {t}")
            options.append((cve, t))
            option_counter += 1
        print(f"  {option_counter}. all")
        options.append((cve, "all"))
        option_counter += 1
        
    if not options:
        print("No trials found to select.")
        return None, None
        
    try:
        selection = input(f"\nSelect a trial (1-{option_counter-1}): ").strip()
        if not selection:
            print(f"Using default option 1: {options[0][0]} / {options[0][1]}")
            return options[0][0], options[0][1]
        else:
            sel_idx = int(selection) - 1
            if 0 <= sel_idx < len(options):
                return options[sel_idx][0], options[sel_idx][1]
            else:
                print("Error: Invalid selection.")
                return None, None
    except (ValueError, IndexError, KeyboardInterrupt):
        print("\nAborted.")
        return None, None

def run_stat_plot(root_dir, cve_list, trial_name_arg, yes):
    venv_activate = os.path.join(root_dir, "../.venv/bin/activate")
    python_bin = sys.executable
    if os.path.isfile(venv_activate):
        python_bin = os.path.abspath(os.path.join(root_dir, "../.venv/bin/python3"))
        
    for cve in cve_list:
        trial_name = trial_name_arg if trial_name_arg else select_trial_interactively(root_dir, cve, yes)
        print(f"Running stat_plot.py on: \033[1;35m{cve}\033[0m with trial: \033[1;35m{trial_name}\033[0m")
        cmd = [python_bin, "scripts/stat_plot.py", "--root", os.path.join(root_dir, "artifact", cve), "--methods", "base", "cd", "dd", "muoafl", "--cve", cve, "--trial-name", trial_name]
        subprocess.run(cmd)
        
    print("\n\033[1;32mDone.\033[0m")

def run_tte_check(root_dir, cve_list, trial_name_arg, yes, registry_value=None):
    venv_activate = os.path.join(root_dir, "../.venv/bin/activate")
    python_bin = sys.executable
    if os.path.isfile(venv_activate):
        python_bin = os.path.abspath(os.path.join(root_dir, "../.venv/bin/python3"))
        
    if trial_name_arg or yes:
        for cve in cve_list:
            trial_name = trial_name_arg if trial_name_arg else select_trial_interactively(root_dir, cve, yes)
            print(f"Running TTE_check.py for {cve} with trial: \033[1;35m{trial_name}\033[0m")
            cmd = [python_bin, "scripts/TTE_check.py", "--bench", cve, "--trial-name", trial_name]
            if registry_value:
                cmd.extend(["--registry", registry_value])
            subprocess.run(cmd)
    else:
        cve, trial_name = select_cve_and_trial_interactively(root_dir, cve_list)
        if not cve or not trial_name:
            sys.exit(0)
        print(f"Running TTE_check.py for {cve} with trial: \033[1;35m{trial_name}\033[0m")
        cmd = [python_bin, "scripts/TTE_check.py", "--bench", cve, "--trial-name", trial_name]
        if registry_value:
            cmd.extend(["--registry", registry_value])
        subprocess.run(cmd)
        
    print("\n\033[1;32mDone.\033[0m")

def run_tte_plot(root_dir, cve_list, trial_name_arg):
    venv_activate = os.path.join(root_dir, "../.venv/bin/activate")
    python_bin = sys.executable
    if os.path.isfile(venv_activate):
        python_bin = os.path.abspath(os.path.join(root_dir, "../.venv/bin/python3"))
        
    for cve in cve_list:
        trial_name = trial_name_arg if trial_name_arg else "all"
        print(f"Running TTE_plot.py for {cve} with trial: \033[1;35m{trial_name}\033[0m")
        cmd = [python_bin, "scripts/TTE_plot.py", "--bench", cve, "--trial-name", trial_name]
        subprocess.run(cmd)

def run_arm_plot(root_dir, cve_list, trial_name_arg):
    venv_activate = os.path.join(root_dir, "../.venv/bin/activate")
    python_bin = sys.executable
    if os.path.isfile(venv_activate):
        python_bin = os.path.abspath(os.path.join(root_dir, "../.venv/bin/python3"))
        
    for cve in cve_list:
        artifact_cve_dir = os.path.join(root_dir, "artifact", cve)
        if not os.path.isdir(artifact_cve_dir):
            print(f"Warning: Artifact directory not found for {cve}. Skipping.")
            continue
        print(f"\n\033[1;34m[ARM Plot]\033[0m Running ARM_plot.py for \033[1;35m{cve}\033[0m...")
        cmd_plot = [python_bin, "scripts/ARM_plot.py", artifact_cve_dir, "--name", cve]
        subprocess.run(cmd_plot)
        
        print(f"\033[1;34m[ARM Stats]\033[0m Running ARM_stats.py (Independence Validation) for \033[1;35m{cve}\033[0m...")
        cmd_stats = [python_bin, "scripts/ARM_stats.py", artifact_cve_dir, "--name", cve]
        subprocess.run(cmd_stats)

def run_ttr(root_dir, cve_list, num_trials, trial_name_arg):
    methods = ["base", "cd", "dd", "muoafl"]
    suffixes = ["afl-base", "afl-cd", "afl-dd", "afl-muoafl"]
    trials = list(range(1, num_trials + 1))
    
    venv_activate = os.path.join(root_dir, "../.venv/bin/activate")
    python_bin = sys.executable
    if os.path.isfile(venv_activate):
        python_bin = os.path.abspath(os.path.join(root_dir, "../.venv/bin/python3"))
        
    for cve in cve_list:
        container_name = f"{cve}-afl-base-1"
        res = subprocess.run(["docker", "ps", "-a", "-q", "-f", f"name=^/{container_name}$"], capture_output=True, text=True)
        if not res.stdout.strip():
            container_name = f"{cve}-afl-dd-1"
            
        session_id = ""
        trial_name = ""
        
        res = subprocess.run(["docker", "ps", "-a", "-q", "-f", f"name=^/{container_name}$"], capture_output=True, text=True)
        if res.stdout.strip():
            inspect_res = subprocess.run(["docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", container_name], capture_output=True, text=True)
            if inspect_res.returncode == 0:
                for line in inspect_res.stdout.splitlines():
                    if line.startswith("SESSION_ID="):
                        session_id = line.split("=", 1)[1].strip()
                    elif line.startswith("TRIAL_NAME="):
                        trial_name = line.split("=", 1)[1].strip()
                        
        if not session_id or not trial_name:
            curr_session_path = os.path.join(root_dir, "bench", cve, ".current_session")
            if os.path.isfile(curr_session_path):
                with open(curr_session_path, 'r') as f:
                    for line in f:
                        if line.startswith("SESSION_ID="):
                            session_id = line.split("=", 1)[1].strip()
                        elif line.startswith("TRIAL_NAME="):
                            trial_name = line.split("=", 1)[1].strip()
                            
        now_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if not trial_name:
            trial_name = f"trial_{now_str}"
        if not session_id:
            session_id = f"session_{now_str}"
            
        artifact_trial_dir = os.path.join(root_dir, "artifact", cve, trial_name)
        if os.path.isdir(artifact_trial_dir):
            exist_session_id = ""
            session_id_file = os.path.join(artifact_trial_dir, ".session_id")
            if os.path.isfile(session_id_file):
                with open(session_id_file, 'r') as f:
                    exist_session_id = f.read().strip()
            if exist_session_id != session_id:
                trial_name = f"{trial_name}_{now_str}"
                artifact_trial_dir = os.path.join(root_dir, "artifact", cve, trial_name)
                
        print(f"Copying TTR logs for trial run: \033[1;35m{trial_name}\033[0m")
        os.makedirs(artifact_trial_dir, exist_ok=True)
        with open(os.path.join(artifact_trial_dir, ".session_id"), "w") as f:
            f.write(session_id)
            
        for idx, method in enumerate(methods):
            suffix = suffixes[idx]
            for i in trials:
                c_name = f"{cve}-{suffix}-{i}"
                res = subprocess.run(["docker", "ps", "-a", "-q", "-f", f"name=^/{c_name}$"], capture_output=True, text=True)
                if not res.stdout.strip():
                    continue
                    
                target_dir = os.path.join(artifact_trial_dir, method, f"trial{i}")
                os.makedirs(target_dir, exist_ok=True)
                print(f"Copying TTR logs from {c_name:<55}... ", end="", flush=True)
                
                copy_all_txt_files(c_name, target_dir)
                
                if suffix in ["afl-base", "afl-cd", "afl-dd"]:
                    slave_c_name = f"{cve}-{suffix}-slave-{i}"
                    copy_all_txt_files(slave_c_name, target_dir, is_slave=True)
                
                res_run = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", c_name], capture_output=True, text=True)
                running = res_run.stdout.strip() == "true"
                
                success = False
                if running:
                    tar_cmd = f"docker exec {c_name} tar -cf - -C /workspace out --exclude=.cur_input --exclude=*.pyc --exclude=__pycache__"
                    try:
                        p1 = subprocess.Popen(tar_cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                        p2 = subprocess.Popen(["tar", "-xf", "-", "-C", target_dir], stdin=p1.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        p1.stdout.close()
                        p2.communicate()
                        success = p2.returncode == 0
                    except Exception:
                        pass
                else:
                    res_cp = subprocess.run(["docker", "cp", f"{c_name}:/workspace/out", target_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    success = res_cp.returncode == 0
                    
                for root, dirs, files in os.walk(target_dir):
                    for file in files:
                        if file.endswith(".pyc"):
                            try:
                                os.remove(os.path.join(root, file))
                            except Exception:
                                pass
                    for d in list(dirs):
                        if d == "__pycache__":
                            try:
                                shutil.rmtree(os.path.join(root, d))
                            except Exception:
                                pass
                
                size_res = subprocess.run(["du", "-sh", os.path.join(target_dir, "out")], capture_output=True, text=True)
                size = size_res.stdout.strip().split()[0] if size_res.returncode == 0 and size_res.stdout.strip() else ""
                
                if success and size:
                    print(f"\033[1;32mDone\033[0m (size: {size})")
                else:
                    print("\033[1;31mFailed\033[0m")
                    
        ttr_cmd = [python_bin, "scripts/TTR.py", "--root", os.path.join(root_dir, "artifact", cve), "--methods", "base", "cd", "dd", "muoafl", "--cve", cve, "--trial-name", trial_name_arg if trial_name_arg else trial_name]
        subprocess.run(ttr_cmd)
        
def detect_num_trials(root_dir, cve_list):
    max_trial = 0
    for cve in cve_list:
        # Check containers
        res = subprocess.run(["docker", "ps", "-a", "--filter", f"name=^/{cve}-afl-", "--format", "{{.Names}}"], capture_output=True, text=True)
        if res.returncode == 0:
            for name in res.stdout.strip().splitlines():
                match = re.search(r'-(\d+)$', name)
                if match:
                    val = int(match.group(1))
                    if val > max_trial:
                        max_trial = val
                        
        # Check volumes
        res_vol = subprocess.run(["docker", "volume", "ls", "--filter", f"name={cve}-afl-", "--format", "{{.Name}}"], capture_output=True, text=True)
        if res_vol.returncode == 0:
            for name in res_vol.stdout.strip().splitlines():
                match = re.search(r'-(\d+)$', name)
                if match:
                    val = int(match.group(1))
                    if val > max_trial:
                        max_trial = val
    if max_trial > 0:
        return max_trial
    return None

def parse_dgf_compile_info(file_path):
    import re
    info = {
        "control": "N.A.",
        "caller": "N.A.",
        "edge_cov": "N.A.",
        "prune": "N.A."
    }
    if not file_path or not os.path.exists(file_path):
        return info
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            m_control = re.search(r'Number of Control BBs.*?:\s*(\d+)', content, re.IGNORECASE)
            if m_control:
                info["control"] = m_control.group(1)
            m_caller = re.search(r'Number of Caller BBs.*?:\s*(\d+)', content, re.IGNORECASE)
            if m_caller:
                info["caller"] = m_caller.group(1)
            m_edge = re.search(r'Total Basic Blocks Edge-Instrumented:\s*(\d+)', content, re.IGNORECASE)
            if m_edge:
                info["edge_cov"] = m_edge.group(1)
            m_prune = re.search(r'Total Basic Blocks Pruned/Removed by DGF:\s*(\d+)', content, re.IGNORECASE)
            if m_prune:
                info["prune"] = m_prune.group(1)
    except Exception as e:
        print(f"Error parsing compile info file {file_path}: {e}")
    return info

def run_summary(root_dir):
    import csv
    import os
    import subprocess
    
    artifact_root = os.path.join(root_dir, "artifact")
    if not os.path.isdir(artifact_root):
        print(f"Error: Artifact directory {artifact_root} not found.")
        return

def run_matrix_plot(root_dir, cve_list):
    python_bin = sys.executable
    for cve in cve_list:
        plot_cmd = [python_bin, "scripts/matrix_plot.py", cve]
        subprocess.run(plot_cmd)
        
    benchmarks = []
    for item in sorted(os.listdir(artifact_root)):
        item_path = os.path.join(artifact_root, item)
        if os.path.isdir(item_path):
            csv_path = os.path.join(item_path, "plot", "TTE_summary_table_dd_muoafl.csv")
            if os.path.isfile(csv_path):
                benchmarks.append((item, csv_path))
                
    if not benchmarks:
        print("No TTE_summary_table_dd_muoafl.csv files found.")
        return
        
    summary_data = []
    for cve, csv_path in benchmarks:
        try:
            cve_dir = os.path.dirname(os.path.dirname(csv_path))
            compile_info_path = None
            dd_func_slice_path = None
            dd_dfg_slice_path = None
            for r, dirs, files in os.walk(cve_dir):
                for f in files:
                    if f in ["dgf_compile_info-cd.txt"]:
                        compile_info_path = os.path.join(r, f)
                    if f.startswith("slice_func-") and "dd" in f and f.endswith(".txt"):
                        dd_func_slice_path = os.path.join(r, f)
                    if f.startswith("slice_dfg-") and "dd" in f and f.endswith(".txt"):
                        dd_dfg_slice_path = os.path.join(r, f)
            
            print(f"found compile_info: {compile_info_path}")
            print(f"found func_slice: {dd_func_slice_path}")
            print(f"found dfg_slice: {dd_dfg_slice_path}")
            
            compile_info = parse_dgf_compile_info(compile_info_path) if compile_info_path else {}
            
            dd_func_slice_count = "N.A."
            if dd_func_slice_path and os.path.isfile(dd_func_slice_path):
                with open(dd_func_slice_path, 'r', encoding='utf-8') as sf:
                    dd_func_slice_count = str(sum(1 for line in sf if line.strip()))
                    
            dd_dfg_slice_count = "N.A."
            if dd_dfg_slice_path and os.path.isfile(dd_dfg_slice_path):
                with open(dd_dfg_slice_path, 'r', encoding='utf-8') as df:
                    dd_dfg_slice_count = str(sum(1 for line in df if line.strip()))
            
            dd_row = {}
            muoafl_row = {}
            with open(csv_path, mode='r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    config = row.get("Configuration", "").lower()
                    if "dd" in config and "muoafl" not in config:
                        dd_row = row
                    elif "muoafl" in config:
                        muoafl_row = row
            
            dd_geo = dd_row.get("Geo Mean TTE", "N.A.")
            dd_success = dd_row.get("Success Rate", "N.A.")
            muoafl_geo = muoafl_row.get("Geo Mean TTE", "N.A.")
            muoafl_success = muoafl_row.get("Success Rate", "N.A.")
            speedup = muoafl_row.get("Speedup", "N.A.")
            p_val = muoafl_row.get("p-value", "N.A.")
            
            dd_max = dd_row.get("Max TTE", "N.A.")
            muoafl_max = muoafl_row.get("Max TTE", "N.A.")
            
            summary_data.append({
                "CVE": cve,
                "CD # control": compile_info.get("control", "N.A."),
                "CD # caller": compile_info.get("caller", "N.A."),
                "CD # edge cov": compile_info.get("edge_cov", "N.A."),
                "CD # prune": compile_info.get("prune", "N.A."),
                "DD # function slice": dd_func_slice_count,
                "DD # dep": dd_dfg_slice_count,
                "dd Geo mean TTE": dd_geo,
                "dd succes rate": dd_success,
                "muoafl Geo mean TTE": muoafl_geo,
                "muoafl succes rate": muoafl_success,
                "speedup": speedup,
                "p-value": p_val,
                "dd Max TTE": dd_max,
                "muoafl Max TTE": muoafl_max
            })
        except Exception as e:
            print(f"Error parsing {csv_path}: {e}")
            
    if not summary_data:
        print("No summary data could be parsed.")
        return
        
    # Write to a CSV file in artifact root
    output_csv = os.path.join(artifact_root, "TTE_overall_summary.csv")
    headers = [
        "CVE", "CD # control", "CD # caller", "CD # edge cov", "CD # prune",
        "DD # function slice", "DD # dep",
        "dd Geo mean TTE", "dd succes rate", "muoafl Geo mean TTE", "muoafl succes rate",
        "speedup", "p-value", "dd Max TTE", "muoafl Max TTE"
    ]
    try:
        with open(output_csv, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(summary_data)
        print(f"\033[1;32mOverall TTE summary table saved as CSV to: {output_csv}\033[0m")
    except Exception as e:
        print(f"Error writing CSV to {output_csv}: {e}")
        
    # Generate overall summary image
    output_png = os.path.join(artifact_root, "TTE_overall_summary.png")
    try:
        import matplotlib.pyplot as plt
        cell_text = [[
            row["CVE"],
            row["CD # control"],
            row["CD # caller"],
            row["CD # edge cov"],
            row["CD # prune"],
            row["DD # function slice"],
            row["DD # dep"],
            row["dd Geo mean TTE"],
            row["dd succes rate"],
            row["muoafl Geo mean TTE"],
            row["muoafl succes rate"],
            row["speedup"],
            row["p-value"],
            row["dd Max TTE"],
            row["muoafl Max TTE"]
        ] for row in summary_data]
        
        fig, ax = plt.subplots(figsize=(16.0, len(summary_data) * 0.4 + 0.8))
        ax.axis('off')
        
        table = ax.table(
            cellText=cell_text,
            colLabels=headers,
            loc='center',
            cellLoc='center'
        )
        table.auto_set_font_size(False)
        table.set_fontsize(8)
        table.scale(1.2, 1.8)
        
        for (r, col_idx), cell in table.get_celld().items():
            if r == 0:
                cell.set_text_props(weight='bold', color='white')
                cell.set_facecolor('#1f77b4')
                cell.set_edgecolor('#1f77b4')
            else:
                if r % 2 == 0:
                    cell.set_facecolor('#f2f2f2')
                else:
                    cell.set_facecolor('white')
                cell.set_edgecolor('#e0e0e0')
                
        plt.tight_layout()
        plt.savefig(output_png, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"\033[1;32mOverall TTE summary table saved as PNG to: {output_png}\033[0m")
    except ImportError:
        print("matplotlib not installed, skipping PNG table generation.")
    except Exception as e:
        print(f"Error generating PNG table: {e}")

def main():
    root_dir = os.path.abspath(os.path.dirname(__file__))
    
    # Automatically re-execute within the virtualenv if it exists and we're not inside it
    venv_python = os.path.abspath(os.path.join(root_dir, "../.venv/bin/python3"))
    if os.path.isfile(venv_python) and os.path.abspath(sys.executable) != venv_python:
        os.execv(venv_python, [venv_python] + sys.argv)
    command, target_cve, num_trials, trial_name_arg, run_all, yes, tags_value, registry_value, only_crashes, extra_args = parse_arguments(root_dir)
    
    if not command:
        print("Error: Command (up, down, build, status, log, clean, copy, stat_plot, tte_check, tte_plot, ttr, summary) is required.")
        print_usage()
        sys.exit(1)

    if command == "build" and target_cve in ["dafl", "cafl", "muoafl"]:
        build_fuzzer_image(root_dir, target_cve, tags_value, registry_value, extra_args)
        sys.exit(0)
        
    cve_list = []
    if command == "down":
        if yes and target_cve:
            cve_list = [target_cve]
        else:
            selected = select_cve_interactively(root_dir, "down", yes)
            if not selected:
                sys.exit(0)
            cve_list = [selected]
    elif command == "up":
        if yes and target_cve:
            cve_list = [target_cve]
        else:
            selected = select_cve_interactively(root_dir, "up", yes)
            if not selected:
                sys.exit(0)
            cve_list = [selected]
    elif command == "clean":
        run_clean()
        sys.exit(0)
    elif command == "summary":
        run_summary(root_dir)
        sys.exit(0)
    else:
        if target_cve:
            cve_list = [target_cve]
        else:
            cve_list = get_cves(root_dir)
            
    if not cve_list:
        print("No active CVEs found to manage.")
        sys.exit(0)
        
    if num_trials is None and command in ["up", "down", "copy"]:
        num_trials = detect_num_trials(root_dir, cve_list)
        if num_trials is None:
            print("Error: Could not detect number of trials. Use --trials N to specify.")
            sys.exit(1)

    # Execute commands
    if command in ["up", "down", "build"]:
        run_docker_compose_command(root_dir, command, cve_list, num_trials, run_all, yes, tags_value, registry_value, extra_args, trial_name_arg)
    elif command == "stop":
        run_stop(cve_list)
    elif command == "copy":
        run_copy(root_dir, cve_list, num_trials, trial_name_arg, only_crashes=only_crashes)
    elif command == "status":
        run_status(cve_list)
    elif command == "log":
        run_log(cve_list)
    elif command == "stat_plot":
        run_stat_plot(root_dir, cve_list, trial_name_arg, yes)
    elif command == "tte_check":
        run_tte_check(root_dir, cve_list, trial_name_arg, yes, registry_value)
    elif command == "tte_plot":
        run_tte_plot(root_dir, cve_list, trial_name_arg)
    elif command == "ttr":
        run_ttr(root_dir, cve_list, num_trials, trial_name_arg)
    elif command == "arm_plot":
        run_arm_plot(root_dir, cve_list, trial_name_arg)
    elif command == "matrix_plot":
        run_matrix_plot(root_dir, cve_list)

if __name__ == "__main__":
    main()

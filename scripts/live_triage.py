#!/usr/bin/env python3
import os
import sys
import shutil
import argparse
import subprocess
import time

def main():
    parser = argparse.ArgumentParser(description="Live Triage on Compute Node")
    parser.add_argument("--cve", required=True, help="CVE name")
    parser.add_argument("--image", required=True, help="Apptainer SIF or Sandbox path")
    parser.add_argument("--local-out", required=True, help="LOCAL_OUT path")
    parser.add_argument("cmd", nargs=argparse.REMAINDER, help="Target binary and args")
    args = parser.parse_args()

    cve = args.cve
    image_path = args.image
    local_out = args.local_out
    
    if not args.cmd:
        print("Error: Target command not provided.")
        sys.exit(1)
        
    binary = args.cmd[0]
    flags = args.cmd[1:]
    
    # Import triage to get target trace
    scripts_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.append(scripts_dir)
    try:
        from triage import get_triage_function_name
        import triage
    except ImportError:
        print("Error: triage.py not found.")
        sys.exit(1)
        
    triage_func_name = get_triage_function_name(cve)
    if not triage_func_name:
        print(f"Error: Could not determine triage function for {cve}")
        sys.exit(1)
        
    triage_func = getattr(triage, triage_func_name, None)
    if not triage_func:
        print(f"Error: Triage function {triage_func_name} not found.")
        sys.exit(1)
        
    # Get the target trace
    import inspect
    source = inspect.getsource(triage_func)
    target_trace = []
    in_trace = False
    for line in source.split('\n'):
        line = line.strip()
        if 'target_trace = [' in line:
            in_trace = True
            continue
        if in_trace and ']' in line:
            break
        if in_trace:
            trace_line = line.strip('",\' \t')
            if trace_line:
                target_trace.append(trace_line)
                
    if not target_trace:
        print("Error: Target trace could not be extracted.")
        sys.exit(1)
        
    # Check both main and slave crashes directories
    crashes_dirs = []
    main_crashes = os.path.join(local_out, "main/crashes")
    if os.path.exists(main_crashes):
        crashes_dirs.append(main_crashes)
    slave_crashes = os.path.join(local_out, "slave/crashes")
    if os.path.exists(slave_crashes):
        crashes_dirs.append(slave_crashes)
    
    # dual method might use dd/crashes and cd/crashes
    dd_crashes = os.path.join(local_out, "dd/crashes")
    if os.path.exists(dd_crashes):
        crashes_dirs.append(dd_crashes)
    cd_crashes = os.path.join(local_out, "cd/crashes")
    if os.path.exists(cd_crashes):
        crashes_dirs.append(cd_crashes)

    if not crashes_dirs:
        print("No crashes directories found yet.")
        sys.exit(0)
        
    exposure_file = os.path.join(local_out, "dgf_target_exposure.txt")
    if os.path.exists(exposure_file):
        print(f"TTE already found: {exposure_file}")
        sys.exit(0)

    best_tte_ms = None
    best_matching_crash = None

    for crashes_dir in crashes_dirs:
        crashes = [f for f in os.listdir(crashes_dir) if f.startswith("id:")]
        if not crashes:
            continue
            
        print(f"Triaging {len(crashes)} crashes in {crashes_dir}...")
        
        # Prepare target trace
        trace_path = os.path.join(crashes_dir, ".target_trace")
        with open(trace_path, 'w') as f:
            for t in target_trace:
                f.write(t + "\n")
                
        # Copy helper scripts
        triage_helper_path = os.path.join(scripts_dir, "container_triage.py")
        with open(triage_helper_path, 'r') as f:
            triage_script_content = f.read().replace("PLACEHOLDER_CVE_NAME", cve)
        with open(os.path.join(crashes_dir, ".triage.py"), 'w') as f:
            f.write(triage_script_content)
            
        shutil.copy(os.path.join(scripts_dir, "triage.py"), os.path.join(crashes_dir, "triage.py"))
        
        result_path = os.path.join(crashes_dir, ".triage_result")
        if os.path.exists(result_path):
            os.remove(result_path)
            
        # Run apptainer to triage
        cmd = [
            "apptainer", "exec",
            "--cleanenv",
            "--containall",
            "--pid",
            "--ipc",
            "--no-home",
            "--bind", f"{crashes_dir}:/workspace/out/main/crashes",
            image_path,
            "python3", "/workspace/out/main/crashes/.triage.py",
            binary
        ] + flags
        
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            print(f"Triage execution failed for {crashes_dir}")
            continue
            
        # Parse result
        if os.path.exists(result_path):
            with open(result_path, 'r') as f:
                res = f.read().strip()
                if res != "None":
                    parts = res.split(',')
                    crash_id = parts[0]
                    crash_time = int(parts[1])
                    if best_tte_ms is None or crash_time < best_tte_ms:
                        best_tte_ms = crash_time
                        best_matching_crash = crash_id
                        
    if best_tte_ms is not None:
        print(f"\n[+] TTE FOUND! Crash ID: {best_matching_crash}, Time: {best_tte_ms} ms")
        with open(exposure_file, "w") as f:
            f.write("Target reached!\n")
            f.write(f"TTE (ms): {best_tte_ms}\n")
            f.write(f"Crash file: {best_matching_crash}\n")
    else:
        print("No matching crashes found yet.")

if __name__ == "__main__":
    main()

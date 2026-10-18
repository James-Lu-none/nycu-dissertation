#!/usr/bin/env python3
"""Generate master compose file for AFLGo Linescore experiments (aflgo, attention, rationale).

Follows bench/linescore/README.md Section 2 & 4:
- Independent image tag: ${CVE}:aflgo-linescore
- Independent service names: aflgo-{i}, attention-{i}, rationale-{i}
- Independent volumes: aflgo-out-{i}, attention-out-{i}, rationale-out-{i}
- Runs via /workspace/run_aflgo.sh with AFLGo power scheduling and non-destructive triage.
"""

import argparse
import os

def generate_compose(num_trials, output_path=None):
    services_lines = ["services:"]
    volumes_lines = ["volumes:"]
    
    for i in range(1, num_trials + 1):
        # Build context specified only on first service
        build_str = ""
        if i == 1:
            build_str = """    build:
      context: "./${CVE}"
      dockerfile: Dockerfile.aflgo-linescore
      args:
        - REGISTRY=${REGISTRY:-docker.io/location0717}\n"""
            
        # 1. AFLGo Physical Distance Baseline
        services_lines.append(f"""  afl-aflgo-{i}:
    container_name: "${{CVE}}-afl-aflgo-{i}"
{build_str}    image: "${{IMAGE_NAME_AFLGO_LINESCORE:-${{CVE}}:aflgo-linescore}}"
    command: bash -c "bash /workspace/run_aflgo.sh && sleep infinity"
    working_dir: /workspace
    pid: "host"
    environment:
      - TARGET_BIN=${{TARGET_BIN_AFLGO:-/workspace/cxxfilt-aflgo}}
      - TARGET_ARGS=${{TARGET_ARGS}}
      - TARGET_BIN_ASAN=${{TARGET_BIN_ASAN:-/workspace/cxxfilt-asan}}
      - FUZZER_BIN=afl-fuzz
      - FUZZER_ROLE=M
      - FUZZER_NAME=main
      - SESSION_ID=${{SESSION_ID}}
      - TRIAL_NAME=${{TRIAL_NAME}}
      - CONTAINER_NAME=${{CVE}}-afl-aflgo-{i}
      - MAX_TIME=${{MAX_TIME:-18000}}
      - ANNEALING_TIME=${{ANNEALING_TIME:-240m}}
    volumes:
      - "afl-out-aflgo-{i}:/workspace/out"
      - "./run_aflgo.sh:/workspace/run_aflgo.sh:ro"
      - "../../artifact/${{CVE}}/${{TRIAL_NAME}}/logs:/workspace/logs"
    deploy:
      resources:
        limits:
          memory: 1.5G
""")
        volumes_lines.append(f"""  afl-out-aflgo-{i}:
    name: "${{CVE}}-afl-out-aflgo-{i}"
""")

        # 2. AFLGo + Local Attention Distance
        services_lines.append(f"""  afl-attention-{i}:
    container_name: "${{CVE}}-afl-attention-{i}"
    image: "${{IMAGE_NAME_AFLGO_LINESCORE:-${{CVE}}:aflgo-linescore}}"
    command: bash -c "bash /workspace/run_aflgo.sh && sleep infinity"
    working_dir: /workspace
    pid: "host"
    environment:
      - TARGET_BIN=${{TARGET_BIN_ATTENTION:-/workspace/cxxfilt-attention}}
      - TARGET_ARGS=${{TARGET_ARGS}}
      - TARGET_BIN_ASAN=${{TARGET_BIN_ASAN:-/workspace/cxxfilt-asan}}
      - FUZZER_BIN=afl-fuzz
      - FUZZER_ROLE=M
      - FUZZER_NAME=main
      - SESSION_ID=${{SESSION_ID}}
      - TRIAL_NAME=${{TRIAL_NAME}}
      - CONTAINER_NAME=${{CVE}}-afl-attention-{i}
      - MAX_TIME=${{MAX_TIME:-18000}}
      - ANNEALING_TIME=${{ANNEALING_TIME:-240m}}
    volumes:
      - "afl-out-attention-{i}:/workspace/out"
      - "./run_aflgo.sh:/workspace/run_aflgo.sh:ro"
      - "../../artifact/${{CVE}}/${{TRIAL_NAME}}/logs:/workspace/logs"
    deploy:
      resources:
        limits:
          memory: 1.5G
""")
        volumes_lines.append(f"""  afl-out-attention-{i}:
    name: "${{CVE}}-afl-out-attention-{i}"
""")

        # 3. AFLGo + Rationale Distance
        services_lines.append(f"""  afl-rationale-{i}:
    container_name: "${{CVE}}-afl-rationale-{i}"
    image: "${{IMAGE_NAME_AFLGO_LINESCORE:-${{CVE}}:aflgo-linescore}}"
    command: bash -c "bash /workspace/run_aflgo.sh && sleep infinity"
    working_dir: /workspace
    pid: "host"
    environment:
      - TARGET_BIN=${{TARGET_BIN_RATIONALE:-/workspace/cxxfilt-rationale}}
      - TARGET_ARGS=${{TARGET_ARGS}}
      - TARGET_BIN_ASAN=${{TARGET_BIN_ASAN:-/workspace/cxxfilt-asan}}
      - FUZZER_BIN=afl-fuzz
      - FUZZER_ROLE=M
      - FUZZER_NAME=main
      - SESSION_ID=${{SESSION_ID}}
      - TRIAL_NAME=${{TRIAL_NAME}}
      - CONTAINER_NAME=${{CVE}}-afl-rationale-{i}
      - MAX_TIME=${{MAX_TIME:-18000}}
      - ANNEALING_TIME=${{ANNEALING_TIME:-240m}}
    volumes:
      - "afl-out-rationale-{i}:/workspace/out"
      - "./run_aflgo.sh:/workspace/run_aflgo.sh:ro"
      - "../../artifact/${{CVE}}/${{TRIAL_NAME}}/logs:/workspace/logs"
    deploy:
      resources:
        limits:
          memory: 1.5G
""")
        volumes_lines.append(f"""  afl-out-rationale-{i}:
    name: "${{CVE}}-afl-out-rationale-{i}"
""")

    full_content = "\n".join(services_lines) + "\n" + "\n".join(volumes_lines)
    
    if not output_path:
        master_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../bench/docker-compose.master.yml"))
    else:
        master_path = os.path.abspath(output_path)
        
    os.makedirs(os.path.dirname(master_path), exist_ok=True)
    with open(master_path, "w") as f:
        f.write(full_content)
        
    ref_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../bench/docker-compose.aflgo-linescore.yml"))
    with open(ref_path, "w") as f:
        f.write(full_content)
        
    print(f"Successfully generated docker-compose.master.yml and docker-compose.aflgo-linescore.yml for {num_trials} trials.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("trials", type=int, nargs="?", default=5)
    parser.add_argument("--output", type=str, default=None, help="Output file path")
    args = parser.parse_args()
    generate_compose(args.trials, args.output)

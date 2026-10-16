import argparse
import os

def generate_compose(num_trials, output_path=None):
    services_lines = ["services:"]
    volumes_lines = ["volumes:"]
    
    for i in range(1, num_trials + 1):
        # only first service needs build context
        build_str = ""
        if i == 1:
            build_str = """    build:
      context: "./${CVE}"
      dockerfile: Dockerfile.linescore
      args:
        - REGISTRY=${REGISTRY:-docker.io/location0717}\n"""
            
        # DAFL baseline
        services_lines.append(f"""  afl-dafl-{i}:
    container_name: "${{CVE}}-afl-dafl-{i}"
{build_str}    image: "${{IMAGE_NAME_LINESCORE:-${{CVE}}:linescore}}"
    command: bash -c "bash script.sh && sleep infinity"
    working_dir: /workspace
    pid: "host"
    environment:
      - TARGET_BIN=${{TARGET_BIN_DAFL}}
      - TARGET_ARGS=${{TARGET_ARGS}}
      - TARGET_BIN_ASAN=${{TARGET_BIN_ASAN}}
      - FUZZER_BIN=afl-fuzz
      - FUZZER_ROLE=M
      - FUZZER_NAME=main
      - SESSION_ID=${{SESSION_ID}}
      - TRIAL_NAME=${{TRIAL_NAME}}
      - CONTAINER_NAME=${{CVE}}-afl-dafl-{i}
    volumes:
      - "afl-out-dafl-{i}:/workspace/out"
      - "./script.sh:/workspace/script.sh:ro"
      - "../../artifact/${{CVE}}/${{TRIAL_NAME}}/logs:/workspace/logs"
    deploy:
      resources:
        limits:
          memory: 1.5G
""")
        volumes_lines.append(f"""  afl-out-dafl-{i}:
    name: "${{CVE}}-afl-out-dafl-{i}"
""")

        # Attention
        services_lines.append(f"""  afl-attention-{i}:
    container_name: "${{CVE}}-afl-attention-{i}"
    image: "${{IMAGE_NAME_LINESCORE:-${{CVE}}:linescore}}"
    command: bash -c "bash script.sh && sleep infinity"
    working_dir: /workspace
    pid: "host"
    environment:
      - TARGET_BIN=${{TARGET_BIN_ATTENTION}}
      - TARGET_ARGS=${{TARGET_ARGS}}
      - TARGET_BIN_ASAN=${{TARGET_BIN_ASAN}}
      - FUZZER_BIN=afl-fuzz
      - FUZZER_ROLE=M
      - FUZZER_NAME=main
      - SESSION_ID=${{SESSION_ID}}
      - TRIAL_NAME=${{TRIAL_NAME}}
      - CONTAINER_NAME=${{CVE}}-afl-attention-{i}
    volumes:
      - "afl-out-attention-{i}:/workspace/out"
      - "./script.sh:/workspace/script.sh:ro"
      - "../../artifact/${{CVE}}/${{TRIAL_NAME}}/logs:/workspace/logs"
    deploy:
      resources:
        limits:
          memory: 1.5G
""")
        volumes_lines.append(f"""  afl-out-attention-{i}:
    name: "${{CVE}}-afl-out-attention-{i}"
""")

        # Rationale
        services_lines.append(f"""  afl-rationale-{i}:
    container_name: "${{CVE}}-afl-rationale-{i}"
    image: "${{IMAGE_NAME_LINESCORE:-${{CVE}}:linescore}}"
    command: bash -c "bash script.sh && sleep infinity"
    working_dir: /workspace
    pid: "host"
    environment:
      - TARGET_BIN=${{TARGET_BIN_RATIONALE}}
      - TARGET_ARGS=${{TARGET_ARGS}}
      - TARGET_BIN_ASAN=${{TARGET_BIN_ASAN}}
      - FUZZER_BIN=afl-fuzz
      - FUZZER_ROLE=M
      - FUZZER_NAME=main
      - SESSION_ID=${{SESSION_ID}}
      - TRIAL_NAME=${{TRIAL_NAME}}
      - CONTAINER_NAME=${{CVE}}-afl-rationale-{i}
    volumes:
      - "afl-out-rationale-{i}:/workspace/out"
      - "./script.sh:/workspace/script.sh:ro"
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
    
    # Primary default path: ../bench/docker-compose.master.yml (included by bench/*/compose.yaml)
    if not output_path:
        master_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../bench/docker-compose.master.yml"))
    else:
        master_path = os.path.abspath(output_path)
        
    os.makedirs(os.path.dirname(master_path), exist_ok=True)
    with open(master_path, "w") as f:
        f.write(full_content)
        
    # Also save a standalone copy to ../bench/docker-compose.linescore.yml for reference
    linescore_ref_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../bench/docker-compose.linescore.yml"))
    with open(linescore_ref_path, "w") as f:
        f.write(full_content)
        
    print(f"Successfully generated docker-compose.master.yml and docker-compose.linescore.yml for {num_trials} trials.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("trials", type=int, nargs="?", default=5)
    parser.add_argument("--output", type=str, default=None, help="Output file path")
    args = parser.parse_args()
    generate_compose(args.trials, args.output)

import argparse
import os

def generate_compose(num_trials, tags_list):
    services_lines = ["services:"]
    volumes_lines = ["volumes:"]
    
    for i in range(1, num_trials + 1):
        # only first service needs build context
        build_str = ""
        if i == 1:
            build_str = """    build:
      context: "./${CVE}"
      dockerfile: Dockerfile
      args:
        - MUOAFL_TAG=${MUOAFL_TAG:-latest}
        - REGISTRY=${REGISTRY:-registry.optixbase.com:30000}\n"""
            
        # Base
        services_lines.append(f"""  afl-base-{i}:
    container_name: "${{CVE}}-afl-base-{i}"
{build_str}    image: "${{IMAGE_NAME}}"
    command: bash -c "bash script.sh && sleep infinity"
    working_dir: /workspace
    pid: "host"
    environment:
      - TARGET_BIN=${{TARGET_BIN_BASE}}
      - TARGET_ARGS=${{TARGET_ARGS}}
      - TARGET_BIN_ASAN=${{TARGET_BIN_ASAN}}
      - FUZZER_BIN=afl-fuzz
      - FUZZER_ROLE=M
      - FUZZER_NAME=main
      - SESSION_ID=${{SESSION_ID}}
      - TRIAL_NAME=${{TRIAL_NAME}}
      - CONTAINER_NAME=${{CVE}}-afl-base-{i}
    volumes:
      - "afl-out-base-{i}:/workspace/out"
      - "./script.sh:/workspace/script.sh:ro"
      - "../../artifact/${{CVE}}/${{TRIAL_NAME}}/logs:/workspace/logs"
    deploy:
      resources:
        limits:
          memory: 1.5G
""")
        volumes_lines.append(f"""  afl-out-base-{i}:
    name: "${{CVE}}-afl-out-base-{i}"
""")

        # CD
        services_lines.append(f"""  afl-cd-{i}:
    container_name: "${{CVE}}-afl-cd-{i}"
    image: "${{IMAGE_NAME}}"
    command: bash -c "bash script.sh && sleep infinity"
    working_dir: /workspace
    pid: "host"
    environment:
      - TARGET_BIN=${{TARGET_BIN_CD}}
      - TARGET_ARGS=${{TARGET_ARGS}}
      - TARGET_BIN_ASAN=${{TARGET_BIN_ASAN}}
      - FUZZER_BIN=afl-fuzz-cd
      - FUZZER_ROLE=M
      - FUZZER_NAME=main
      - SESSION_ID=${{SESSION_ID}}
      - TRIAL_NAME=${{TRIAL_NAME}}
      - CONTAINER_NAME=${{CVE}}-afl-cd-{i}
    volumes:
      - "afl-out-cd-{i}:/workspace/out"
      - "./script.sh:/workspace/script.sh:ro"
      - "../../artifact/${{CVE}}/${{TRIAL_NAME}}/logs:/workspace/logs"
    deploy:
      resources:
        limits:
          memory: 1.5G
""")
        volumes_lines.append(f"""  afl-out-cd-{i}:
    name: "${{CVE}}-afl-out-cd-{i}"
""")

        # DD
        services_lines.append(f"""  afl-dd-{i}:
    container_name: "${{CVE}}-afl-dd-{i}"
    image: "${{IMAGE_NAME}}"
    command: bash -c "bash script.sh && sleep infinity"
    working_dir: /workspace
    pid: "host"
    environment:
      - TARGET_BIN=${{TARGET_BIN_SOLO_DD}}
      - TARGET_ARGS=${{TARGET_ARGS}}
      - TARGET_BIN_ASAN=${{TARGET_BIN_ASAN}}
      - FUZZER_BIN=afl-fuzz-solo-dd
      - FUZZER_ROLE=M
      - FUZZER_NAME=main
      - SESSION_ID=${{SESSION_ID}}
      - TRIAL_NAME=${{TRIAL_NAME}}
      - CONTAINER_NAME=${{CVE}}-afl-dd-{i}
    volumes:
      - "afl-out-dd-{i}:/workspace/out"
      - "./script.sh:/workspace/script.sh:ro"
      - "../../artifact/${{CVE}}/${{TRIAL_NAME}}/logs:/workspace/logs"
    deploy:
      resources:
        limits:
          memory: 1.5G
""")
        volumes_lines.append(f"""  afl-out-dd-{i}:
    name: "${{CVE}}-afl-out-dd-{i}"
""")

        # MUOAFL
        for tag in tags_list:
            services_lines.append(f"""  afl-muoafl-{tag}-{i}:
    container_name: "${{CVE}}-afl-muoafl-{tag}-{i}"
    image: "${{IMAGE_NAME}}"
    command: bash -c "bash script.sh && sleep infinity"
    working_dir: /workspace
    pid: "host"
    environment:
      - TARGET_BIN=${{TARGET_BIN_MUOAFL}}-{tag}
      - TARGET_ARGS=${{TARGET_ARGS}}
      - TARGET_BIN_ASAN=${{TARGET_BIN_ASAN}}
      - FUZZER_BIN=afl-fuzz-dd-muoafl-{tag}
      - FUZZER_ROLE=M
      - FUZZER_NAME=main
      - MUOAFL_TAG={tag}
      - AFL_SEMANTIC_MAP=/workspace/semantic_map.csv
      - SESSION_ID=${{SESSION_ID}}
      - TRIAL_NAME=${{TRIAL_NAME}}
      - CONTAINER_NAME=${{CVE}}-afl-muoafl-{tag}-{i}
    volumes:
      - "afl-out-muoafl-{tag}-{i}:/workspace/out"
      - "./script.sh:/workspace/script.sh:ro"
      - "../../artifact/${{CVE}}/${{TRIAL_NAME}}/logs:/workspace/logs"
    deploy:
      resources:
        limits:
          memory: 1.5G
""")
            volumes_lines.append(f"""  afl-out-muoafl-{tag}-{i}:
    name: "${{CVE}}-afl-out-muoafl-{tag}-{i}"
""")

    full_content = "\n".join(services_lines) + "\n" + "\n".join(volumes_lines)
    
    # write to ../bench/docker-compose.master.yml
    master_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../bench/docker-compose.master.yml"))
    
    # make sure parent directory exists
    os.makedirs(os.path.dirname(master_path), exist_ok=True)
    
    with open(master_path, "w") as f:
        f.write(full_content)
    print(f"Successfully generated docker-compose.master.yml for {num_trials} trials.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("trials", type=int, nargs="?", default=5)
    parser.add_argument("--tags", type=str, default="v1")
    args = parser.parse_args()
    tags_list = [t.strip() for t in args.tags.split(",") if t.strip()]
    if not tags_list:
        tags_list = ["v1"]
    generate_compose(args.trials, tags_list)


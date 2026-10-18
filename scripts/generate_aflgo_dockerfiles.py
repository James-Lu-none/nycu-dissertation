#!/usr/bin/env python3
"""Generate Dockerfile.aflgo-linescore for all benchmarks in sources.json.

Creates a standardized, clean, multi-stage Dockerfile that builds:
1. Physical distance AFLGo target ({bin}-aflgo)
2. Attention distance AFLGo target ({bin}-attention)
3. Rationale distance AFLGo target ({bin}-rationale)
4. ASAN triage target ({bin}-asan)
and creates symlinks to target-aflgo, target-attention, target-rationale, target-asan.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH_DIR = ROOT / "bench"
BENCH_SRC_DIR = BENCH_DIR / "src"
SOURCES_JSON = BENCH_SRC_DIR / "sources.json"



def get_project_spec(bench_name: str, src_root_name: str):
    """Determine build parameters for a given benchmark project."""
    if "binutils" in bench_name:
        bin_map = {
            "cxxfilt": ("cxxfilt", "cxxfilt"),
            "strip": ("strip-new", "strip"),
            "objcopy": ("objcopy", "objcopy"),
            "objdump": ("objdump", "objdump"),
            "nm": ("nm-new", "nm"),
            "readelf": ("readelf", "readelf"),
        }
        build_bin, bin_alias = None, None
        for k, (b, a) in bin_map.items():
            if f"_{k}_" in bench_name:
                build_bin, bin_alias = b, a
                break
        if not build_bin:
            parts = bench_name.split("_")
            alias = parts[1] if len(parts) >= 2 else "cxxfilt"
            build_bin = "strip-new" if alias == "strip" else ("nm-new" if alias == "nm" else alias)
            bin_alias = alias

        return {
            "family": "binutils",
            "src_dir": src_root_name,
            "extra_deps": "",
            "is_out_of_tree": True,
            "configure_cmd": (
                f"/src/{src_root_name}/configure "
                f"--disable-shared --disable-gdb --disable-libdecnumber "
                f"--disable-readline --disable-sim --disable-ld --disable-werror"
            ),
            "build_cmd": "make -j$(nproc)",
            "bin_rel_path": f"binutils/{build_bin}",
            "bin_alias": bin_alias,
        }

    elif "libxml2" in bench_name:
        return {
            "family": "libxml2",
            "src_dir": src_root_name,
            "extra_deps": "",
            "is_out_of_tree": False,
            "configure_cmd": "./autogen.sh --disable-shared --without-python",
            "build_cmd": "make -j$(nproc)",
            "bin_rel_path": "xmllint",
            "bin_alias": "xmllint",
        }

    elif "libming" in bench_name:
        return {
            "family": "libming",
            "src_dir": src_root_name,
            "extra_deps": "",
            "is_out_of_tree": False,
            "configure_cmd": './autogen.sh && ./configure --disable-shared --disable-freetype CFLAGS="-g -O3 -fcommon"',
            "build_cmd": "make -j$(nproc) -C src && make -j$(nproc) -C util swftophp",
            "bin_rel_path": "util/swftophp",
            "bin_alias": "swftophp",
        }

    elif "libjpeg" in bench_name:
        extra_deps = "RUN apt-get update && apt-get install -y --no-install-recommends nasm && rm -rf /var/lib/apt/lists/*\n"
        return {
            "family": "libjpeg",
            "src_dir": src_root_name,
            "extra_deps": extra_deps,
            "is_out_of_tree": False,
            "configure_cmd": 'cmake -G"Unix Makefiles" .',
            "build_cmd": "make -j$(nproc) cjpeg-static",
            "bin_rel_path": "cjpeg-static",
            "bin_alias": "cjpeg",
        }

    elif "lrzip" in bench_name:
        extra_deps = "RUN apt-get update && apt-get install -y --no-install-recommends libbz2-dev liblzo2-dev && rm -rf /var/lib/apt/lists/*\n"
        return {
            "family": "lrzip",
            "src_dir": src_root_name,
            "extra_deps": extra_deps,
            "is_out_of_tree": False,
            "configure_cmd": "./autogen.sh && ./configure",
            "build_cmd": "make -j$(nproc)",
            "bin_rel_path": "lrzip",
            "bin_alias": "lrzip",
        }

    else:
        raise ValueError(f"Unknown benchmark family for '{bench_name}'")


def generate_dockerfile_content(spec: dict) -> str:
    src_dir = spec["src_dir"]
    extra_deps = spec["extra_deps"]
    conf = spec["configure_cmd"]
    bcmd = spec["build_cmd"]
    bin_rel = spec["bin_rel_path"]
    bin_alias = spec["bin_alias"]
    is_oot = spec["is_out_of_tree"]

    if is_oot:
        aflgo_workdir = "/src/obj-aflgo"
        att_workdir = "/src/obj-attention"
        rat_workdir = "/src/obj-rationale"
        asan_workdir = "/src/obj-asan"
        bin_prefix_aflgo = f"/src/obj-aflgo/{bin_rel}"
        bin_prefix_att = f"/src/obj-attention/{bin_rel}"
        bin_prefix_rat = f"/src/obj-rationale/{bin_rel}"
        bin_prefix_asan = f"/src/obj-asan/{bin_rel}"
    else:
        aflgo_workdir = f"/src/{src_dir}"
        att_workdir = f"/src/{src_dir}"
        rat_workdir = f"/src/{src_dir}"
        asan_workdir = f"/src/{src_dir}"
        bin_prefix_aflgo = f"/src/{src_dir}/{bin_rel}"
        bin_prefix_att = f"/src/{src_dir}/{bin_rel}"
        bin_prefix_rat = f"/src/{src_dir}/{bin_rel}"
        bin_prefix_asan = f"/src/{src_dir}/{bin_rel}"

    return f"""# Multi-stage build for AFLGo Linescore Experiment (aflgo baseline, attention, rationale)
# Implements exact physical distance adaptation d = d_phys * (1.5 - w) from Eq. 7-9
ARG REGISTRY=docker.io/location0717
FROM aflgo:toolchain AS source-prep

WORKDIR /src
COPY download.sh .
{extra_deps}RUN bash download.sh

# Offline analysis is produced by scripts/generate_aflgo_distances.py.
# The benchmark consumes distance files only; model inference never runs here.
FROM source-prep AS distance-input
COPY distance.physical.cfg.txt distance.attention.cfg.txt distance.rationale.cfg.txt /src/analysis/
RUN test -s /src/analysis/distance.physical.cfg.txt && \\
    test -s /src/analysis/distance.attention.cfg.txt && \\
    test -s /src/analysis/distance.rationale.cfg.txt

# Stage 2: Physical Baseline (aflgo)
FROM source-prep AS aflgo-build
COPY --from=distance-input /src/analysis/distance.physical.cfg.txt /tmp/distance.cfg.txt
WORKDIR {aflgo_workdir}
ENV CC=aflgo-clang
ENV CXX=aflgo-clang++
RUN CFLAGS="-g -O3 -distance=/tmp/distance.cfg.txt" CXXFLAGS="-g -O3 -distance=/tmp/distance.cfg.txt" \\
    {conf} && \\
    {bcmd}

# Stage 2: Attention Distance
FROM source-prep AS attention-build
COPY --from=distance-input /src/analysis/distance.attention.cfg.txt /tmp/distance.cfg.txt
WORKDIR {att_workdir}
ENV CC=aflgo-clang
ENV CXX=aflgo-clang++
RUN CFLAGS="-g -O3 -distance=/tmp/distance.cfg.txt" CXXFLAGS="-g -O3 -distance=/tmp/distance.cfg.txt" \\
    {conf} && \\
    {bcmd}

# Stage 2: Rationale Distance
FROM source-prep AS rationale-build
COPY --from=distance-input /src/analysis/distance.rationale.cfg.txt /tmp/distance.cfg.txt
WORKDIR {rat_workdir}
ENV CC=aflgo-clang
ENV CXX=aflgo-clang++
RUN CFLAGS="-g -O3 -distance=/tmp/distance.cfg.txt" CXXFLAGS="-g -O3 -distance=/tmp/distance.cfg.txt" \\
    {conf} && \\
    {bcmd}

# Stage 2: ASAN Build for live crash triage
FROM source-prep AS asan-build
WORKDIR {asan_workdir}
ENV CC=clang
ENV CXX=clang++
ENV ASAN_OPTIONS=detect_leaks=0
RUN CFLAGS="-g -O3 -fsanitize=address" CXXFLAGS="-g -O3 -fsanitize=address" \\
    {conf} && \\
    {bcmd}

# Runtime Environment
FROM aflgo:toolchain AS runtime
WORKDIR /workspace
RUN mkdir -p in out logs
COPY seed/ in/
RUN cp /aflgo/scripts/run_aflgo.sh /workspace/run_aflgo.sh
COPY --from=distance-input /src/analysis/distance.physical.cfg.txt /workspace/
COPY --from=distance-input /src/analysis/distance.attention.cfg.txt /workspace/
COPY --from=distance-input /src/analysis/distance.rationale.cfg.txt /workspace/
COPY --from=aflgo-build {bin_prefix_aflgo} /workspace/{bin_alias}-aflgo
COPY --from=attention-build {bin_prefix_att} /workspace/{bin_alias}-attention
COPY --from=rationale-build {bin_prefix_rat} /workspace/{bin_alias}-rationale
COPY --from=asan-build {bin_prefix_asan} /workspace/{bin_alias}-asan
RUN ln -sf /workspace/{bin_alias}-aflgo /workspace/target-aflgo && \\
    ln -sf /workspace/{bin_alias}-attention /workspace/target-attention && \\
    ln -sf /workspace/{bin_alias}-rationale /workspace/target-rationale && \\
    ln -sf /workspace/{bin_alias}-asan /workspace/target-asan
"""


def main():
    parser = argparse.ArgumentParser(description="Generate Dockerfile.aflgo-linescore for benchmarks.")
    parser.add_argument("benchmark", nargs="?", default=None, help="Generate for a specific benchmark")
    parser.add_argument("--dry-run", action="store_true", help="Print without writing")
    args = parser.parse_args()

    if not SOURCES_JSON.is_file():
        print(f"Error: {SOURCES_JSON} not found", file=sys.stderr)
        sys.exit(1)

    with open(SOURCES_JSON, "r", encoding="utf-8") as f:
        sources_data = json.load(f)

    project_specs = {}
    for item in sources_data:
        roots = item.get("roots", [])
        if not roots:
            continue
        src_root_name = Path(roots[0]).name
        for proj in item.get("projects", []):
            try:
                project_specs[proj] = get_project_spec(proj, src_root_name)
            except Exception as e:
                print(f"Warning: Skipping {proj}: {e}", file=sys.stderr)

    targets = [args.benchmark] if args.benchmark else sorted(project_specs.keys())

    count = 0
    for proj in targets:
        if proj not in project_specs:
            print(f"Error: Project '{proj}' not in sources.json catalog", file=sys.stderr)
            continue

        spec = project_specs[proj]
        content = generate_dockerfile_content(spec)

        bench_dir = BENCH_DIR / proj
        if not bench_dir.is_dir():
            print(f"Warning: Directory {bench_dir} does not exist, skipping", file=sys.stderr)
            continue

        dockerfile_path = bench_dir / "Dockerfile.aflgo-linescore"

        if args.dry_run:
            print(f"[DRY-RUN] Would write {dockerfile_path} (spec: {spec['family']}, bin: {spec['bin_alias']})")
        else:
            dockerfile_path.write_text(content, encoding="utf-8")
            print(f"[SUCCESS] Wrote {dockerfile_path}")
            count += 1

    print(f"\nDone! Generated {count} Dockerfile.aflgo-linescore files.")


if __name__ == "__main__":
    main()

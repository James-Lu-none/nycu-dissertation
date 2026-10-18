#!/usr/bin/env python3
"""Extract AFLGo CG, CFGs, block mappings, and physical distances for benchmarks.

Implements Steps 6 & 7 from aflgo/Readme.md:
  Step 6: Build target with aflgo-clang/clang++ to extract CFGs, dot files, BBnames, BBcalls, and block_mappings.
  Step 7: Clean BBnames.txt / BBcalls.txt and run gen_distance_fast.py to generate distance.cfg.txt.
Outputs BBnames.txt, BBcalls.txt, distance.cfg.txt, distance.physical.cfg.txt, and block_mapping.jsonl
directly back to each benchmark directory.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH_DIR = ROOT / "bench"
BENCH_SRC_DIR = BENCH_DIR / "src"
SOURCES_JSON = BENCH_SRC_DIR / "sources.json"


# Recipe catalog for benchmark families
def get_benchmark_recipe(bench_name: str, src_root_name: str) -> dict:
    """Return dict with recipe specs for building benchmark."""
    if "binutils" in bench_name:
        bin_map = {
            "cxxfilt": "cxxfilt",
            "strip": "strip-new",
            "objcopy": "objcopy",
            "objdump": "objdump",
            "nm": "nm-new",
            "readelf": "readelf",
        }
        target_bin = None
        for k, v in bin_map.items():
            if f"_{k}_" in bench_name:
                target_bin = v
                break
        if not target_bin:
            parts = bench_name.split("_")
            target_bin = parts[1] if len(parts) >= 2 else "cxxfilt"

        return {
            "family": "binutils",
            "is_oot": True,
            "extra_deps": "",
            "configure_cmd": (
                "/tmp/src/configure --disable-shared --disable-gdb --disable-libdecnumber "
                "--disable-readline --disable-sim --disable-ld --disable-werror"
            ),
            "build_cmd": "make -j$(nproc)",
            "bin_subdir": "binutils",
            "bin_name": target_bin,
        }

    elif "libxml2" in bench_name:
        return {
            "family": "libxml2",
            "is_oot": False,
            "extra_deps": "",
            "configure_cmd": "./autogen.sh --disable-shared --without-python",
            "build_cmd": "make -j$(nproc) xmllint",
            "bin_subdir": ".",
            "bin_name": "xmllint",
        }

    elif "libming" in bench_name:
        return {
            "family": "libming",
            "is_oot": False,
            "extra_deps": "",
            "configure_cmd": './autogen.sh && ./configure --disable-shared --disable-freetype CFLAGS="-g -O3 -fcommon $ADDITIONAL"',
            "build_cmd": "make -j$(nproc) -C src && make -j$(nproc) -C util swftophp",
            "bin_subdir": "util",
            "bin_name": "swftophp",
        }

    elif "libjpeg" in bench_name:
        return {
            "family": "libjpeg",
            "is_oot": False,
            "extra_deps": "apt-get update && apt-get install -y --no-install-recommends nasm && rm -rf /var/lib/apt/lists/*",
            "configure_cmd": 'cmake -G"Unix Makefiles" -DCMAKE_C_COMPILER=aflgo-clang -DCMAKE_CXX_COMPILER=aflgo-clang++ .',
            "build_cmd": "make -j$(nproc) cjpeg-static",
            "bin_subdir": ".",
            "bin_name": "cjpeg-static",
        }

    elif "lrzip" in bench_name:
        return {
            "family": "lrzip",
            "is_oot": False,
            "extra_deps": "apt-get update && apt-get install -y --no-install-recommends libbz2-dev liblzo2-dev && rm -rf /var/lib/apt/lists/*",
            "configure_cmd": "./autogen.sh && ./configure",
            "build_cmd": "make -j$(nproc)",
            "bin_subdir": ".",
            "bin_name": "lrzip",
        }

    else:
        raise ValueError(f"Unknown benchmark family for '{bench_name}'")


def load_sources_map():
    """Map benchmark project names to their source code directory under bench/src."""
    if not SOURCES_JSON.is_file():
        raise FileNotFoundError(f"Missing {SOURCES_JSON}")
    with open(SOURCES_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    project_to_src = {}
    for entry in data:
        key = entry["key"]
        for proj in entry.get("projects", []):
            roots = entry.get("roots", [])
            if roots:
                folder_name = Path(roots[0]).name
                src_path = BENCH_SRC_DIR / key / folder_name
            else:
                src_path = BENCH_SRC_DIR / key
            project_to_src[proj] = src_path
    return project_to_src


def extract_target_from_bench(bench_dir: Path, target_line_override: str = None) -> str:
    """Extract target string from BBtargets.txt or trace file."""
    if target_line_override:
        return target_line_override.strip()

    bbtargets_path = bench_dir / "BBtargets.txt"
    if bbtargets_path.is_file():
        content = bbtargets_path.read_text().strip()
        if content:
            return content

    trace_path = bench_dir / "trace"
    if trace_path.is_file():
        lines = [line.strip() for line in trace_path.read_text().splitlines() if line.strip()]
        if lines:
            return lines[0]

    raise ValueError(f"No target found in {bench_dir} (neither BBtargets.txt nor trace found)")


def run_stage1_for_benchmark(
    bench_name: str,
    image: str = "aflgo:toolchain",
    target_override: str = None,
    output_dir: Path = None,
    dry_run: bool = False,
    skip_existing: bool = False,
):
    bench_dir = BENCH_DIR / bench_name
    if not bench_dir.is_dir():
        raise FileNotFoundError(f"Benchmark directory not found: {bench_dir}")

    dest_dir = output_dir or bench_dir
    dest_dir.mkdir(parents=True, exist_ok=True)

    if skip_existing:
        expected = [
            "BBnames.txt",
            "BBcalls.txt",
            "distance.cfg.txt",
            "distance.physical.cfg.txt",
            "block_mapping.jsonl",
        ]
        if all((dest_dir / f).is_file() and (dest_dir / f).stat().st_size > 0 for f in expected):
            print(f"[{bench_name}] Artifacts already exist, skipping (--skip-existing)")
            return

    sources_map = load_sources_map()
    if bench_name not in sources_map:
        raise KeyError(f"Benchmark '{bench_name}' not found in {SOURCES_JSON}")

    src_root = sources_map[bench_name]
    if not src_root.is_dir():
        raise FileNotFoundError(f"Source root does not exist: {src_root}")

    # Extract target
    target_str = extract_target_from_bench(bench_dir, target_override)
    print(f"[{bench_name}] Target: {target_str}")
    print(f"[{bench_name}] Source root: {src_root}")

    # Get recipe
    recipe = get_benchmark_recipe(bench_name, src_root.name)

    # Temporary directory on host for docker analysis output
    temp_analysis_dir = dest_dir / "analysis_tmp"
    if temp_analysis_dir.exists():
        shutil.rmtree(temp_analysis_dir, ignore_errors=True)
        if temp_analysis_dir.exists():
            subprocess.run(
                ["docker", "run", "--rm", "-v", f"{temp_analysis_dir.resolve()}:/cleanup", image, "bash", "-c", "rm -rf /cleanup/*"],
                check=False,
            )
            shutil.rmtree(temp_analysis_dir, ignore_errors=True)
    temp_analysis_dir.mkdir(parents=True, exist_ok=True)

    # Prepare initial BBtargets.txt
    (temp_analysis_dir / "BBtargets.txt").write_text(target_str + "\n")

    extra_deps_cmd = f"{recipe['extra_deps']}\n" if recipe.get("extra_deps") else ""

    if recipe["is_oot"]:
        dir_setup = """mkdir -p /tmp/obj-stage1
cd /tmp/obj-stage1"""
        bin_dir = f"/tmp/obj-stage1/{recipe['bin_subdir']}"
    else:
        dir_setup = "cd /tmp/src"
        bin_dir = f"/tmp/src/{recipe['bin_subdir']}"

    docker_script = f"""set -euo pipefail

{extra_deps_cmd}
echo "=== Copying source to /tmp/src ==="
cp -r /src_orig /tmp/src

{dir_setup}

echo "=== Setting up AFLGo environment (Step 6) ==="
export CC=aflgo-clang
export CXX=aflgo-clang++
export ADDITIONAL="-targets=/analysis/BBtargets.txt -outdir=/analysis -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
export CFLAGS="-g -O3 $ADDITIONAL"
export CXXFLAGS="-g -O3 $ADDITIONAL"

echo "=== Configuring subject ==="
{recipe['configure_cmd']}

echo "=== Building subject ==="
{recipe['build_cmd']}

echo "=== Cleaning BBnames and BBcalls (Step 7) ==="
if [ -f /analysis/BBnames.txt ]; then
    cat /analysis/BBnames.txt | grep -v "^$" | rev | cut -d: -f2- | rev | sort | uniq > /analysis/BBnames.txt.tmp && mv /analysis/BBnames.txt.tmp /analysis/BBnames.txt
fi

if [ -f /analysis/BBcalls.txt ]; then
    cat /analysis/BBcalls.txt | grep -Ev "^[^,]*$|^([^,]*,){{2,}}[^,]*$" | sort | uniq > /analysis/BBcalls.txt.tmp && mv /analysis/BBcalls.txt.tmp /analysis/BBcalls.txt
fi

echo "=== Consolidating block_mappings ==="
if [ -d /analysis/block_mappings ]; then
    cat /analysis/block_mappings/*.jsonl > /analysis/block_mapping.jsonl
fi

echo "=== Resolving target basic blocks ==="
python3 -c "
import json, sys
from pathlib import Path

targets_file = Path('/analysis/BBtargets.txt')
bbnames_file = Path('/analysis/BBnames.txt')
mapping_file = Path('/analysis/block_mapping.jsonl')

if targets_file.is_file() and bbnames_file.is_file():
    targets = [t.strip() for t in targets_file.read_text().splitlines() if t.strip()]
    bbnames = set(line.strip() for line in bbnames_file.read_text().splitlines() if line.strip())

    matched = [t for t in targets if t in bbnames]
    unmatched = [t for t in targets if t not in bbnames]

    resolved = list(matched)
    if unmatched and mapping_file.is_file():
        line_to_block = {{}}
        for line in mapping_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                dkey = obj.get('distance_key')
                if not dkey or dkey not in bbnames:
                    continue
                for sline in obj.get('source_lines', []):
                    f = Path(sline.get('file', '')).name
                    l = sline.get('line')
                    line_to_block[f'{{f}}:{{l}}'] = dkey
            except Exception:
                pass

        for u in unmatched:
            if u in line_to_block:
                resolved_key = line_to_block[u]
                if resolved_key not in resolved:
                    resolved.append(resolved_key)
                    print(f'Mapped target {{u}} -> basic block {{resolved_key}}')
            else:
                print(f'Warning: Target {{u}} could not be resolved in block mapping')

    if resolved:
        targets_file.write_text('\\n'.join(resolved) + '\\n')
"

echo "=== Computing physical distances (Step 7) ==="
TARGET_BIN_DIR="{bin_dir}"
python3 /aflgo/distance/gen_distance_fast.py "$TARGET_BIN_DIR" /analysis "{recipe['bin_name']}"

if [ -f /analysis/distance.cfg.txt ]; then
    cp /analysis/distance.cfg.txt /analysis/distance.physical.cfg.txt
    echo "=== Distance generation successful ==="
else
    echo "ERROR: distance.cfg.txt was not generated!" >&2
    exit 1
fi

chmod -R 777 /analysis || true
"""

    docker_cmd = [
        "docker", "run", "--rm",
        "-v", f"{src_root.resolve()}:/src_orig:ro",
        "-v", f"{temp_analysis_dir.resolve()}:/analysis",
        image,
        "bash", "-c", docker_script,
    ]

    if dry_run:
        print("Dry run mode. Docker command:")
        print(" ".join(docker_cmd))
        return

    print(f"[{bench_name}] Running AFLGo Stage 1 inside {image}...")
    proc = subprocess.run(docker_cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"[{bench_name}] ERROR: Docker execution failed!")
        print("STDOUT:\n", proc.stdout[-2000:])
        print("STDERR:\n", proc.stderr[-2000:])
        raise RuntimeError(f"Stage 1 failed for {bench_name} with exit code {proc.returncode}")

    # Verify generated files
    expected_files = [
        "BBnames.txt",
        "BBcalls.txt",
        "distance.cfg.txt",
        "distance.physical.cfg.txt",
        "block_mapping.jsonl",
    ]
    for fname in expected_files:
        fpath = temp_analysis_dir / fname
        if not fpath.is_file() or fpath.stat().st_size == 0:
            raise RuntimeError(f"Expected output file missing or empty: {fpath}")

    # Copy artifacts back to benchmark directory
    for fname in expected_files:
        src_file = temp_analysis_dir / fname
        dest_file = dest_dir / fname
        shutil.copy2(src_file, dest_file)
        print(f"[{bench_name}] -> Exported {fname} ({dest_file.stat().st_size} bytes)")

    # Also keep BBtargets.txt (with resolved basic block key)
    resolved_targets = temp_analysis_dir / "BBtargets.txt"
    if resolved_targets.is_file():
        shutil.copy2(resolved_targets, dest_dir / "BBtargets.txt")

    # Cleanup temporary analysis directory
    shutil.rmtree(temp_analysis_dir, ignore_errors=True)

    print(f"[{bench_name}] Step 6 & 7 extraction complete! Files written to {dest_dir}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Extract AFLGo CG, CFGs, and distance.cfg.txt (Steps 6 & 7) via aflgo image."
    )
    parser.add_argument(
        "benchmark",
        nargs="?",
        default="binutils-2.26_cxxfilt_CVE-2016-4487",
        help="Benchmark project name (default: binutils-2.26_cxxfilt_CVE-2016-4487)",
    )
    parser.add_argument(
        "--image",
        default="aflgo:toolchain",
        help="AFLGo docker image (default: aflgo:toolchain)",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Override target line (e.g., 'cplus-dem.c:4319')",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        type=Path,
        help="Custom output directory (default: bench/<benchmark>)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print docker command without running",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run extraction for all benchmarks in sources.json",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip benchmarks that already have valid output distance files",
    )

    args = parser.parse_args()

    if args.all:
        sources_map = load_sources_map()
        for b in sorted(sources_map.keys()):
            try:
                run_stage1_for_benchmark(
                    b,
                    image=args.image,
                    target_override=args.target,
                    output_dir=args.output_dir,
                    dry_run=args.dry_run,
                    skip_existing=args.skip_existing,
                )
            except Exception as e:
                print(f"[{b}] Failed: {e}", file=sys.stderr)
    else:
        run_stage1_for_benchmark(
            args.benchmark,
            image=args.image,
            target_override=args.target,
            output_dir=args.output_dir,
            dry_run=args.dry_run,
            skip_existing=args.skip_existing,
        )


if __name__ == "__main__":
    main()

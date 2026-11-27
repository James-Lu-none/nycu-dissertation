#!/usr/bin/env python3
"""build_sources.py - Build LLVM bitcode and instrumented binaries for projects.

Uses modular build scripts specified in sources.yaml to build sources in Docker.
Zero hardcoded cases. Cleanly outputs to build_artifacts/<source_id>/<target_binary>/.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Set
import yaml

from fetch_sources import fetch_single_source

ROOT_DIR = Path(__file__).resolve().parent.parent
PARENT_DIR = ROOT_DIR.parent


def resolve_container_path(host_path: Path) -> str:
    """Resolve host path to its container-mapped path."""
    try:
        rel = host_path.resolve().relative_to(ROOT_DIR.resolve())
        return f"/workspace/{rel}"
    except ValueError:
        pass
    try:
        rel = host_path.resolve().relative_to(PARENT_DIR.resolve())
        return f"/dissertation/{rel}"
    except ValueError:
        pass
    raise ValueError(f"Path {host_path} is outside ROOT_DIR and PARENT_DIR")


def build_source(
    source_id: str,
    source_meta: Dict[str, Any],
    artifacts_dir: Path,
    image: str = "target-graph:llvm14",
    force: bool = False,
    fetch: bool = False,
) -> bool:
    build_script = source_meta.get("build_script")
    if not build_script:
        print(f"[SKIP] {source_id}: No build_script defined in sources.yaml")
        return False

    script_path = ROOT_DIR / build_script
    if not script_path.is_file():
        print(f"[ERROR] {source_id}: Build script not found at {script_path}", file=sys.stderr)
        return False

    local_path = (ROOT_DIR / source_meta["local_path"]).resolve()
    if not local_path.exists() or fetch:
        print(f"[FETCH] Source directory missing or --fetch requested for {source_id}...")
        ok = fetch_single_source(source_id, source_meta, ROOT_DIR, force=fetch)
        if not ok or not local_path.exists():
            print(f"[ERROR] {source_id}: Failed to fetch source to {local_path}", file=sys.stderr)
            return False

    out_dir = artifacts_dir / source_id
    if force and out_dir.exists():
        try:
            shutil.rmtree(out_dir)
        except PermissionError:
            subprocess.run(
                ["docker", "run", "--rm", "-v", f"{ROOT_DIR}:/workspace", image, "rm", "-rf", f"/workspace/build_artifacts/{source_id}"],
                check=True,
            )
    out_dir.mkdir(parents=True, exist_ok=True)

    # Check if already built
    if not force:
        bc_files = list(out_dir.rglob("*.bc"))
        pass_summaries = list(out_dir.rglob("pass_summary.json"))
        if bc_files and pass_summaries:
            print(f"[CACHE] {source_id}: Already built ({len(bc_files)} bc files). Use --force to rebuild.")
            return True

    print(f"\n========================================================")
    print(f"[BUILD] Building source: {source_id}")
    print(f"  Script: {build_script}")
    print(f"  Source: {local_path}")
    print(f"  Output: {out_dir}")
    print(f"========================================================")

    c_script = resolve_container_path(script_path)
    c_source = resolve_container_path(local_path)
    c_out = f"/workspace/build_artifacts/{source_id}"

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{ROOT_DIR}:/workspace",
        "-v", f"{PARENT_DIR}:/dissertation:ro",
        "-e", f"SOURCE_ID={source_id}",
        image,
        "bash", c_script, c_source, c_out, source_id,
    ]

    ret = subprocess.run(cmd)
    if ret.returncode != 0:
        print(f"[FAIL] {source_id}: Build script exited with code {ret.returncode}", file=sys.stderr)
        return False

    # Ensure permissions
    subprocess.run(["chmod", "-R", "a+rw", str(out_dir)], stderr=subprocess.DEVNULL)

    bc_files = list(out_dir.rglob("*.bc"))
    pass_summaries = list(out_dir.rglob("pass_summary.json"))
    if not bc_files or not pass_summaries:
        print(f"[WARN] {source_id}: Build completed but missing *.bc or pass_summary.json in {out_dir}", file=sys.stderr)
        return False

    print(f"[SUCCESS] {source_id}: Successfully built {len(bc_files)} targets.")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sources-yaml",
        type=Path,
        default=ROOT_DIR / "configs/projects/sources.yaml",
        help="Path to sources.yaml",
    )
    parser.add_argument(
        "--benchmark",
        type=Path,
        help="Optional benchmark YAML to build only required sources",
    )
    parser.add_argument(
        "--source",
        type=str,
        help="Build a specific source ID",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=ROOT_DIR / "build_artifacts",
        help="Directory to store compiled artifacts",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force rebuild even if artifacts exist",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Fetch/update sources from upstream before building",
    )
    parser.add_argument(
        "--image",
        type=str,
        default="target-graph:llvm14",
        help="Docker image for building",
    )
    args = parser.parse_args()

    with open(args.sources_yaml, "r", encoding="utf-8") as f:
        sources_data = yaml.safe_load(f).get("sources", {})

    target_sources: Set[str] = set()
    if args.source:
        if args.source not in sources_data:
            print(f"Error: source {args.source} not found in {args.sources_yaml}", file=sys.stderr)
            sys.exit(1)
        target_sources.add(args.source)
    elif args.benchmark:
        with open(args.benchmark, "r", encoding="utf-8") as f:
            bench_data = yaml.safe_load(f).get("cases", [])
        for c in bench_data:
            target_sources.add(c["source_id"])
    else:
        target_sources = set(sources_data.keys())

    print(f"Building {len(target_sources)} source(s)...")
    successes = 0
    failures = []

    for sid in sorted(target_sources):
        meta = sources_data.get(sid)
        if not meta:
            print(f"[ERROR] Source {sid} not in sources.yaml", file=sys.stderr)
            failures.append(sid)
            continue
        ok = build_source(sid, meta, args.artifacts_dir, image=args.image, force=args.force, fetch=args.fetch)
        if ok:
            successes += 1
        else:
            failures.append(sid)

    print("\n" + "=" * 50)
    print(f"Build Summary: {successes}/{len(target_sources)} succeeded.")
    if failures:
        print(f"Failures: {', '.join(failures)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

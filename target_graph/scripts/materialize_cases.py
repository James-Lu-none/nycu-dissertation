#!/usr/bin/env python3
"""materialize_cases.py - Materialize benchmark cases from build artifacts.

Reads benchmark YAML and links/copies:
1. src -> ../../sources/<source_id>
2. <target_binary>.bc, pass_summary.json, bb_map.jsonl, <target_binary>_inst
3. PoC files into cases/<case_id>/
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent


def find_artifact_dir(artifacts_dir: Path, source_id: str, target_binary: str) -> Path | None:
    """Find the directory containing the compiled artifacts for target_binary."""
    base = artifacts_dir / source_id
    if not base.is_dir():
        return None

    # Check subdirectory first (e.g. build_artifacts/cJSON-1.7.8/cjson_test)
    sub = base / target_binary
    if (sub / f"{target_binary}.bc").is_file():
        return sub

    # Check base directory
    if (base / f"{target_binary}.bc").is_file():
        return base

    return None


def materialize_single_case(
    case_meta: Dict[str, Any],
    cases_dir: Path,
    artifacts_dir: Path,
    sources_dir: Path,
    force: bool = False,
) -> bool:
    cid = case_meta["case_id"]
    sid = case_meta["source_id"]
    target_bin = case_meta["target_binary"]

    cdir = cases_dir / cid
    cdir.mkdir(parents=True, exist_ok=True)

    # 1. Symlink source directory
    src_link = cdir / "src"
    target_source = sources_dir / sid
    if not target_source.exists():
        print(f"[FAIL] {cid}: Source link target does not exist: {target_source}", file=sys.stderr)
        return False

    if src_link.is_symlink() or src_link.exists():
        if src_link.is_symlink():
            src_link.unlink()
        elif src_link.is_dir():
            shutil.rmtree(src_link)
        else:
            src_link.unlink()
    src_link.symlink_to(Path("../../sources") / sid)

    # 2. Link/Copy compiled artifacts
    art_dir = find_artifact_dir(artifacts_dir, sid, target_bin)
    if not art_dir:
        print(f"[FAIL] {cid}: Missing artifacts for {sid}/{target_bin} in {artifacts_dir}", file=sys.stderr)
        return False

    # Required files for graph and SVF analysis
    req_files = [
        (f"{target_bin}.bc", f"{target_bin}.bc"),
        ("pass_summary.json", "pass_summary.json"),
        ("bb_map.jsonl", "bb_map.jsonl"),
        ("inst_map.jsonl", "inst_map.jsonl"),
    ]
    # Optional execution binaries
    opt_files = [
        (f"{target_bin}_inst", f"{target_bin}_inst"),
        (f"{target_bin}_base", f"{target_bin}_base"),
    ]

    for src_name, dst_name in req_files:
        s = art_dir / src_name
        d = cdir / dst_name
        if not s.is_file():
            print(f"[FAIL] {cid}: Required artifact {src_name} not found in {art_dir}", file=sys.stderr)
            return False
        shutil.copyfile(s, d)

    for src_name, dst_name in opt_files:
        s = art_dir / src_name
        d = cdir / dst_name
        if s.is_file():
            shutil.copy2(s, d)
        elif d.exists():
            d.unlink()

    # 3. Setup PoC
    poc_src = case_meta.get("poc_path")
    poc_sha256 = case_meta.get("poc_sha256")
    poc_dst = cdir / "poc"
    if poc_src:
        p_src = Path(poc_src) if Path(poc_src).is_absolute() else (ROOT_DIR / poc_src)
        if p_src.is_file():
            if poc_sha256:
                actual_hash = hashlib.sha256(p_src.read_bytes()).hexdigest()
                if actual_hash.lower() != poc_sha256.lower():
                    print(f"[FAIL] {cid}: PoC SHA256 mismatch at {p_src} ({actual_hash} != {poc_sha256})", file=sys.stderr)
                    return False
            shutil.copyfile(p_src, poc_dst)
            # Create extension symlinks if helpful (e.g. poc.tif, poc.json, dummy.jpg)
            ext = p_src.suffix
            if ext and ext != ".poc":
                ext_dst = cdir / f"poc{ext}"
                if ext_dst.is_symlink() or ext_dst.exists():
                    ext_dst.unlink()
                try:
                    ext_dst.symlink_to("poc")
                except Exception:
                    pass
        else:
            print(f"[WARN] {cid}: PoC not found at {p_src}")

    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=ROOT_DIR / "configs/projects/benchmark_30_cases.yaml",
        help="Path to benchmark cases YAML",
    )
    parser.add_argument(
        "--cases-dir",
        type=Path,
        default=ROOT_DIR / "cases",
        help="Directory to materialize cases",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=ROOT_DIR / "build_artifacts",
        help="Directory containing compiled source artifacts",
    )
    parser.add_argument(
        "--sources-dir",
        type=Path,
        default=ROOT_DIR / "sources",
        help="Directory containing source trees",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force overwrite existing case artifacts",
    )
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        cases = yaml.safe_load(f).get("cases", [])

    print(f"Materializing {len(cases)} cases from {args.artifacts_dir} into {args.cases_dir}...")
    successes = 0
    failures = []

    for c in cases:
        cid = c["case_id"]
        ok = materialize_single_case(
            c,
            args.cases_dir,
            args.artifacts_dir,
            args.sources_dir,
            force=args.force,
        )
        if ok:
            successes += 1
        else:
            failures.append(cid)

    print("\n" + "=" * 50)
    print(f"Materialization Summary: {successes}/{len(cases)} cases ready.")
    if failures:
        print(f"Failed cases: {', '.join(failures)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

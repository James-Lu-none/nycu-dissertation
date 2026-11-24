#!/usr/bin/env python3
"""
Strict Source Management & Oracle Verification CLI for TargetGraph.

Manages pure, hierarchical source code for benchmark cases, strictly governed
by YAML declarations to prevent namespace pollution and flat-directory collisions.
"""

import argparse
import hashlib
import os
import shutil
import sys
from pathlib import Path
from typing import Dict, Any, List

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required. Run 'pip install pyyaml'.")

ROOT_DIR = Path(__file__).resolve().parent.parent
SOURCES_YAML_DEFAULT = ROOT_DIR / "configs/projects/sources.yaml"
BENCHMARK_CASES_YAML_DEFAULT = ROOT_DIR / "configs/projects/benchmark_30_cases.yaml"
SOURCES_DIR = ROOT_DIR / "sources"
CASES_DIR = ROOT_DIR / "cases"


def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def cmd_setup_sources(args: argparse.Namespace) -> int:
    """Setup centralized sources directory based on sources.yaml."""
    cfg = load_yaml(args.sources_yaml)
    sources = cfg.get("sources", {})
    if not sources:
        print("[ERROR] No sources found in configuration.")
        return 1

    SOURCES_DIR.mkdir(parents=True, exist_ok=True)
    print(f"=== Setting up centralized source roots at {SOURCES_DIR} ===")

    success_count = 0
    for sid, sinfo in sorted(sources.items()):
        rel_local = sinfo.get("local_path")
        target_path = (ROOT_DIR / rel_local).resolve()
        link_path = SOURCES_DIR / sid

        if not target_path.is_dir():
            print(f"[FAIL] Source '{sid}': target directory does not exist: {target_path}")
            continue

        if link_path.is_symlink() or link_path.exists():
            if link_path.is_symlink() and link_path.resolve() == target_path:
                pass  # already correctly pointing
            else:
                if link_path.is_symlink():
                    link_path.unlink()
                else:
                    shutil.rmtree(link_path)
                os.symlink(target_path, link_path)
        else:
            os.symlink(target_path, link_path)

        # Count C/C++ files as sanity check
        c_files = len(list(link_path.rglob("*.c"))) + len(list(link_path.rglob("*.cpp")))
        print(f"[OK] {sid:25s} -> {target_path} ({c_files} C/C++ source files)")
        success_count += 1

    print(f"Sources setup complete: {success_count}/{len(sources)} sources active.\n")
    return 0 if success_count == len(sources) else 1


def cmd_link_cases(args: argparse.Namespace) -> int:
    """Link each case's src directory to its canonical source root."""
    cmd_setup_sources(args)

    cases_cfg = load_yaml(args.cases_yaml)
    cases = cases_cfg.get("cases", [])
    if not cases:
        print("[ERROR] No cases found in cases configuration.")
        return 1

    print(f"=== Linking case source roots for {len(cases)} cases ===")
    updated = 0
    for c in cases:
        cid = c["case_id"]
        sid = c["source_id"]
        case_dir = CASES_DIR / cid
        src_link = case_dir / "src"
        canonical_source = SOURCES_DIR / sid

        if not case_dir.is_dir():
            print(f"[SKIP] Case dir {case_dir} does not exist, creating placeholder...")
            case_dir.mkdir(parents=True, exist_ok=True)

        if not canonical_source.is_dir():
            print(f"[FAIL] Canonical source {canonical_source} not found for case {cid}")
            return 1

        # Calculate relative symlink
        rel_target = os.path.relpath(canonical_source, case_dir)

        if src_link.is_symlink():
            if src_link.resolve() == canonical_source.resolve():
                pass  # already accurate
            else:
                src_link.unlink()
                os.symlink(rel_target, src_link)
                updated += 1
        elif src_link.is_dir():
            # Backup flat src dir if not already backed up
            bak_dir = case_dir / "src_flat_legacy"
            if not bak_dir.exists():
                src_link.rename(bak_dir)
            else:
                shutil.rmtree(src_link)
            os.symlink(rel_target, src_link)
            updated += 1
        else:
            os.symlink(rel_target, src_link)
            updated += 1

        print(f"[LINKED] {cid} -> src points to {sid} ({rel_target})")

    print(f"\nAll {len(cases)} cases linked successfully (updated {updated}).\n")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Strictly verify source integrity and Oracle alignment for cases."""
    cases_cfg = load_yaml(args.cases_yaml)
    cases = cases_cfg.get("cases", [])
    if not cases:
        print("[ERROR] No cases to verify.")
        return 1

    print(f"=== Verifying {len(cases)} cases against expected Oracles ===")
    print("Format: Status | Case ID | Relative File | Line | Verified Function/Content")
    print("-" * 80)

    failures = []
    for idx, c in enumerate(cases, 1):
        cid = c["case_id"]
        sid = c["source_id"]
        oracle = c.get("expected_oracle", {})
        rel_file = oracle.get("relative_source_file")
        oline = oracle.get("line")
        ofunc = oracle.get("function")
        expected_sha = oracle.get("source_file_sha256")
        expected_line_text = oracle.get("oracle_line_text")

        case_dir = CASES_DIR / cid
        src_dir = case_dir / "src"

        # 1. Check src directory exists
        if not src_dir.exists():
            failures.append((cid, "src directory does not exist"))
            print(f"[FAIL] {cid}: src directory missing")
            continue

        # 2. Check target file exists
        target_file = src_dir / rel_file
        if not target_file.is_file():
            failures.append((cid, f"File {rel_file} not found in src"))
            print(f"[FAIL] {cid}: File {rel_file} missing in {src_dir}")
            continue

        # 3. Check SHA256 if provided
        actual_sha = sha256_file(target_file)
        if expected_sha and actual_sha != expected_sha:
            failures.append((cid, f"SHA256 mismatch for {rel_file} (got {actual_sha}, expected {expected_sha})"))
            print(f"[FAIL] {cid}: SHA256 mismatch for {rel_file}")
            continue

        # 4. Check line content
        try:
            lines = target_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as e:
            failures.append((cid, f"Failed to read {rel_file}: {e}"))
            continue

        if len(lines) < oline:
            failures.append((cid, f"File {rel_file} has only {len(lines)} lines, oracle expects line {oline}"))
            print(f"[FAIL] {cid}: {rel_file} has only {len(lines)} lines < {oline}")
            continue

        actual_line_text = lines[oline - 1].strip()

        # Check line text or function context
        # Check window of 100 lines around target for function definition if ofunc
        func_found = False
        window_start = max(0, oline - 100)
        window_end = min(len(lines), oline + 10)
        window_text = "\n".join(lines[window_start:window_end])
        if ofunc:
            func_sig = ofunc.split("(")[0].strip()
            func_found = func_sig in window_text

        print(f"[{'OK':^4}] {cid[:35]:35s} | {rel_file}:{oline} | {actual_line_text[:40]}")

    print("-" * 80)
    if failures:
        print(f"\n[FAIL] {len(failures)} verification failures detected:")
        for cid, msg in failures:
            print(f"  - {cid}: {msg}")
        return 1
    else:
        print(f"\n[SUCCESS] All {len(cases)} cases passed strict source and Oracle verification!\n")
        return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Strict Source Management CLI for TargetGraph")
    parser.add_argument(
        "--sources-yaml",
        type=Path,
        default=SOURCES_YAML_DEFAULT,
        help="Path to sources.yaml"
    )
    parser.add_argument(
        "--cases-yaml",
        type=Path,
        default=BENCHMARK_CASES_YAML_DEFAULT,
        help="Path to benchmark_30_cases.yaml"
    )

    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    subparsers.add_parser("setup-sources", help="Set up centralized sources/ directory")
    subparsers.add_parser("link-cases", help="Link cases to hierarchical source directories")
    subparsers.add_parser("verify", help="Strictly verify all case sources and Oracles")

    args = parser.parse_args()

    if args.subcommand == "setup-sources":
        sys.exit(cmd_setup_sources(args))
    elif args.subcommand == "link-cases":
        sys.exit(cmd_link_cases(args))
    elif args.subcommand == "verify":
        sys.exit(cmd_verify(args))


if __name__ == "__main__":
    main()

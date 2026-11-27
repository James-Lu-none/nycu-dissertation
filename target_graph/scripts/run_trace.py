#!/usr/bin/env python3
"""run_trace.py - Universal declarative trace runner for benchmark cases.

Reads benchmark YAML (e.g. benchmark_30_cases.yaml) and executes PoC against
instrumented binaries in Docker. Zero hardcoded case logic.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR / "src") not in sys.path:
    sys.path.insert(0, str(ROOT_DIR / "src"))

import json
from target_graph.llvm.mapping import BasicBlockMapper
from target_graph.tracing.evidence import asan_evidence, sha256
from target_graph.tracing.symbolizer import (
    parse_trace_bb_ids,
    parse_trace_pcs,
    trace_to_basic_blocks,
)


def write_trace_bbs_json(cid: str, cdir: Path, inst_bin: Path, trace_file: Path) -> Path:
    """Only emit verified, canonical BB IDs from the LLVM instrumented binary."""
    direct_bbs = parse_trace_bb_ids(trace_file)
    if direct_bbs is None or not direct_bbs:
        raise ValueError(
            "Expected direct 16-hex-digit LLVM BB trace; legacy PC symbolization "
            "is not permitted as execution ground truth"
        )
    mapper = BasicBlockMapper(cdir / "bb_map.jsonl")
    unknown = set(direct_bbs) - set(mapper.bb_records)
    if unknown:
        raise ValueError(
            f"Direct trace contains {len(unknown)} BB IDs missing from bb_map "
            "(instrumented binary / bitcode / build identity mismatch)"
        )
    unique_bbs = list(dict.fromkeys(direct_bbs))
    out_path = cdir / "trace_bbs.json"
    payload = {
        "schema_version": 2,
        "case_id": cid,
        "trace_file": trace_file.name,
        "trace_mode": "direct_bb_id",
        "mapping_method": "LLVM_IR_BASIC_BLOCK_ENTRY",
        "total_bb_events": len(direct_bbs),
        "num_executed_bbs": len(unique_bbs),
        "executed_bbs_unique": unique_bbs,
        "executed_bbs_ordered": direct_bbs,
        "instrumented_binary_sha256": sha256(inst_bin),
        "bitcode_sha256": sha256(cdir / f"{inst_bin.name[:-5]}.bc"),
        "poc_sha256": sha256(cdir / "poc"),
        "bb_map_sha256": sha256(cdir / "bb_map.jsonl"),
        "trace_file_sha256": sha256(trace_file),
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out_path


def run_single_trace(
    case_meta: Dict[str, Any],
    cases_dir: Path,
    image: str = "target-graph:llvm14",
    force: bool = False,
    timeout_sec: int = 60,
) -> Dict[str, Any]:
    cid = case_meta["case_id"]
    cdir = cases_dir / cid
    target_bin = case_meta["target_binary"]

    trace_file = cdir / "trace_crash.txt"
    stderr_file = cdir / "crash_stderr.txt"
    trace_bbs_file = cdir / "trace_bbs.json"
    exit_file = cdir / "trace_exit_code.txt"
    run_meta_file = cdir / "trace_run.json"

    res = {
        "case_id": cid,
        "success": False,
        "trace_size": 0,
        "stderr_lines": 0,
        "error": None,
    }

    # Always clean stale trace outputs before re-running (no cache reuse)
    for stale in (trace_file, stderr_file, trace_bbs_file, exit_file, run_meta_file):
        if stale.exists():
            stale.unlink()

    inst_bin = cdir / f"{target_bin}_inst"
    if not inst_bin.is_file():
        res["error"] = f"Missing instrumented binary {inst_bin}"
        return res

    # Construct container command
    c_bin = f"/workspace/cases/{cid}/{target_bin}_inst"
    c_poc = f"/workspace/cases/{cid}/poc"

    poc_cmd_template = case_meta.get("poc_cmd")
    if not poc_cmd_template:
        poc_cmd_template = ["{binary}", "{poc}"]

    c_cmd_parts = []
    for arg in poc_cmd_template:
        arg_str = str(arg)
        arg_str = arg_str.replace("{binary}", c_bin).replace("{poc}", c_poc)
        c_cmd_parts.append(arg_str)

    quoted_cmd = " ".join(shlex.quote(p) for p in c_cmd_parts)

    c_trace = f"/workspace/cases/{cid}/trace_crash.txt"
    c_stderr = f"/workspace/cases/{cid}/crash_stderr.txt"

    poc_stdin = case_meta.get("poc_stdin")
    stdin_redirect = ""
    if poc_stdin:
        # If stdin is specified as a file or token
        stdin_path = cdir / poc_stdin if not Path(poc_stdin).is_absolute() else Path(poc_stdin)
        if stdin_path.is_file():
            stdin_redirect = f"< /workspace/cases/{cid}/{poc_stdin}"
        else:
            stdin_redirect = f"< /workspace/cases/{cid}/poc"

    inner_script = f"""
set -uo pipefail
export TARGET_GRAPH_TRACE_FILE="{c_trace}"
export ASAN_SYMBOLIZER_PATH="/usr/bin/llvm-symbolizer"
export ASAN_OPTIONS="abort_on_error=0:symbolize=1:strip_path_prefix=/workspace/:handle_segv=1"
rm -f "{c_trace}" "{c_stderr}"

set +e
{quoted_cmd} {stdin_redirect} > /dev/null 2> "{c_stderr}"
status=$?
printf '%s\n' "$status" > "/workspace/cases/{cid}/trace_exit_code.txt"
exit 0
"""

    docker_cmd = [
        "docker", "run", "--rm",
        "-v", f"{ROOT_DIR}:/workspace",
        image,
        "bash", "-c", inner_script,
    ]

    try:
        proc = subprocess.run(docker_cmd, timeout=timeout_sec, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"Docker trace runner failed: exit={proc.returncode}")
        if not exit_file.is_file():
            raise RuntimeError("Trace runner missing real PoC exit-code record")
        exit_code = int(exit_file.read_text(encoding="ascii").strip())
        stderr_text = stderr_file.read_text(encoding="utf-8", errors="replace") if stderr_file.is_file() else ""
        oracle_evidence = asan_evidence(stderr_text, case_meta.get("expected_oracle", {}))
        run_meta = {
            "schema_version": 1,
            "case_id": cid,
            "poc_exit_code": exit_code,
            "instrumented_binary_sha256": sha256(inst_bin),
            "poc_sha256": sha256(cdir / "poc") if (cdir / "poc").is_file() else None,
            "bitcode_sha256": sha256(cdir / f"{target_bin}.bc") if (cdir / f"{target_bin}.bc").is_file() else None,
            "stderr_sha256": sha256(stderr_file) if stderr_file.is_file() else None,
            "trace_file_sha256": sha256(trace_file) if trace_file.is_file() else None,
            **oracle_evidence,
        }
        run_meta_file.write_text(json.dumps(run_meta, indent=2) + "\n", encoding="utf-8")
        res["poc_exit_code"] = exit_code
        res["crash_reproduced"] = oracle_evidence["crash_reproduced"]
        res["stderr_lines"] = len(stderr_text.splitlines())
        if not trace_file.is_file() or trace_file.stat().st_size == 0:
            raise RuntimeError("No dynamic trace recorded")
        res["trace_size"] = trace_file.stat().st_size
        write_trace_bbs_json(cid, cdir, inst_bin, trace_file)
        # A trace exists independently of whether the PoC reproduced its oracle.
        # The audit must additionally verify source provenance and SVF evidence.
        res["success"] = bool(exit_code != 0 and oracle_evidence["crash_reproduced"])
        if not res["success"]:
            res["error"] = "Oracle ASan fault was not reproduced (check trace_run.json)"
    except subprocess.TimeoutExpired:
        res["error"] = f"Execution timed out ({timeout_sec}s)"
    except Exception as e:
        res["error"] = str(e)

    return res


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
        help="Directory containing case folders",
    )
    parser.add_argument(
        "--case",
        type=str,
        help="Run trace for a specific case ID",
    )
    parser.add_argument(
        "--jobs", "-j",
        type=int,
        default=4,
        help="Parallel execution jobs",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-run trace even if already present",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Per-case timeout in seconds",
    )
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        cases = yaml.safe_load(f).get("cases", [])

    if args.case:
        cases = [c for c in cases if c["case_id"] == args.case]
        if not cases:
            print(f"Error: case {args.case} not found in {args.config}", file=sys.stderr)
            sys.exit(1)

    print(f"Executing PoC trace for {len(cases)} cases (jobs={args.jobs})...")
    results = []

    if args.jobs <= 1 or len(cases) == 1:
        for idx, c in enumerate(cases, 1):
            cid = c["case_id"]
            print(f"[{idx:02d}/{len(cases):02d}] Tracing {cid}...", end="", flush=True)
            res = run_single_trace(c, args.cases_dir, force=args.force, timeout_sec=args.timeout)
            results.append(res)
            st = "SUCCESS" if res["success"] else "FAIL"
            print(f" -> {st} (trace: {res['trace_size']} bytes, stderr: {res['stderr_lines']} lines)")
            if res["error"]:
                print(f"     Reason: {res['error']}")
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
            future_to_c = {
                executor.submit(run_single_trace, c, args.cases_dir, force=args.force, timeout_sec=args.timeout): c
                for c in cases
            }
            completed = 0
            for future in concurrent.futures.as_completed(future_to_c):
                completed += 1
                c = future_to_c[future]
                cid = c["case_id"]
                res = future.result()
                results.append(res)
                st = "SUCCESS" if res["success"] else "FAIL"
                print(f"[{completed:02d}/{len(cases):02d}] Tracing {cid} -> {st} (trace: {res['trace_size']} bytes, stderr: {res['stderr_lines']} lines)")
                if res["error"]:
                    print(f"     Reason: {res['error']}")

    success_cnt = sum(1 for r in results if r["success"])
    print("\n" + "=" * 50)
    print(f"Trace Summary: {success_cnt}/{len(cases)} succeeded.")


if __name__ == "__main__":
    main()

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
from target_graph.tracing.symbolizer import (
    parse_trace_bb_ids,
    parse_trace_pcs,
    trace_to_basic_blocks,
)


def write_trace_bbs_json(cid: str, cdir: Path, inst_bin: Path, trace_file: Path) -> Path:
    """Parse direct BB-ID trace (or symbolize legacy PC trace) and persist trace_bbs.json."""
    direct_bbs = parse_trace_bb_ids(trace_file)
    if direct_bbs is not None:
        trace_mode = "direct_bb_id"
        ordered_bbs: List[str] = []
        for bb in direct_bbs:
            if not ordered_bbs or ordered_bbs[-1] != bb:
                ordered_bbs.append(bb)
        unique_bbs = list(dict.fromkeys(ordered_bbs))
        total_events = len(direct_bbs)
        unique_events = len(unique_bbs)
    else:
        trace_mode = "pc_symbolize"
        bb_map_path = cdir / "bb_map.jsonl"
        mapper = BasicBlockMapper(bb_map_path)
        pcs = parse_trace_pcs(trace_file)
        ordered_bbs = trace_to_basic_blocks(trace_file, inst_bin, mapper)
        unique_bbs = list(dict.fromkeys(ordered_bbs))
        total_events = len(pcs)
        unique_events = len(set(pcs))

    out_path = cdir / "trace_bbs.json"
    payload = {
        "case_id": cid,
        "trace_file": str(trace_file.name),
        "trace_mode": trace_mode,
        "total_pc_events": total_events,
        "unique_pcs": unique_events,
        "num_executed_bbs": len(unique_bbs),
        "executed_bbs_unique": unique_bbs,
        "executed_bbs_ordered": ordered_bbs,
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

    res = {
        "case_id": cid,
        "success": False,
        "trace_size": 0,
        "stderr_lines": 0,
        "error": None,
    }

    if not force and trace_file.is_file() and trace_file.stat().st_size > 0:
        res["success"] = True
        res["trace_size"] = trace_file.stat().st_size
        if stderr_file.is_file():
            res["stderr_lines"] = sum(1 for _ in open(stderr_file, "r", errors="ignore"))
        inst_bin = cdir / f"{target_bin}_inst"
        if not (cdir / "trace_bbs.json").is_file() and inst_bin.is_file() and (cdir / "bb_map.jsonl").is_file():
            try:
                write_trace_bbs_json(cid, cdir, inst_bin, trace_file)
            except Exception as e:
                res["error"] = f"Failed to symbolize cached trace: {e}"
        return res

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

{quoted_cmd} {stdin_redirect} > /dev/null 2> "{c_stderr}" || true
"""

    docker_cmd = [
        "docker", "run", "--rm",
        "-v", f"{ROOT_DIR}:/workspace",
        image,
        "bash", "-c", inner_script,
    ]

    try:
        subprocess.run(docker_cmd, timeout=timeout_sec, check=False)
        # Ensure permissions
        subprocess.run(["chmod", "a+rw", str(trace_file)], stderr=subprocess.DEVNULL)
        subprocess.run(["chmod", "a+rw", str(stderr_file)], stderr=subprocess.DEVNULL)

        if trace_file.is_file() and trace_file.stat().st_size > 0:
            res["success"] = True
            res["trace_size"] = trace_file.stat().st_size
            if (cdir / "bb_map.jsonl").is_file():
                write_trace_bbs_json(cid, cdir, inst_bin, trace_file)
        if stderr_file.is_file():
            res["stderr_lines"] = sum(1 for _ in open(stderr_file, "r", errors="ignore"))
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

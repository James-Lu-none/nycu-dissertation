#!/usr/bin/env python3
"""Calibrate LLVM target candidates without silently rewriting fault sites.

SVFG seed existence alone does NOT prove fault-operand identity. Default run
emits diagnostic proposals only; --apply requires explicit human approvals.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent


def get_canonical_provenance(case_dir: Path, bc_name: str) -> Tuple[str, str]:
    cmd = [
        sys.executable, "-m", "target_graph.svf.provenance",
        "--pass-summary", str(case_dir / "pass_summary.json"),
        "--bitcode-name", bc_name,
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{ROOT_DIR}/src:{env.get('PYTHONPATH', '')}"
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True, env=env)
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return lines[0], lines[1]


def ensure_tagged_bc(case_id: str, case_dir: Path, bc_name: str, build_id: str, module_name: str, image: str = "target-graph:svf-llvm14") -> None:
    out_dir = case_dir / "svf_backend"
    out_dir.mkdir(parents=True, exist_ok=True)
    tagged_bc = out_dir / "tagged.bc"
    before_jsonl = out_dir / "before.jsonl"
    for stale in (tagged_bc, before_jsonl):
        if stale.exists():
            stale.unlink()

    c_script = f"""
set -euo pipefail
out="/workspace/cases/{case_id}/svf_backend"
bc="/workspace/cases/{case_id}/{bc_name}"
plugin=/usr/local/lib/DGIdentityPass.so
opt -load-pass-plugin="$plugin" -passes=dg-tag -o "$out/tagged.bc" "$bc"
TARGET_GRAPH_DG_EXPORT="$out/before.jsonl" opt -load-pass-plugin="$plugin" -passes=dg-export -disable-output "$out/tagged.bc"
"""
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{ROOT_DIR}:/workspace",
        "-e", f"TARGET_GRAPH_BUILD_ID={build_id}",
        "-e", f"TARGET_GRAPH_ID_MODULE_NAME={module_name}",
        image, "bash", "-c", c_script,
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    subprocess.run(["chmod", "-R", "a+rw", str(out_dir)], stderr=subprocess.DEVNULL)


def test_target_candidates(case_id: str, candidates: List[str], image: str = "target-graph:svf-llvm14", timeout: int = 120) -> Optional[str]:
    if not candidates:
        return None
    # Join with comma
    cand_str = ",".join(candidates)
    c_script = f"""
set -uo pipefail
out="/workspace/cases/{case_id}/svf_backend"
extapi="/opt/SVF/Release-build/svf-llvm/extapi.bc"
rm -f "$out/test_svfg.json"

targetgraph-svf \
  --input "$out/tagged.bc" \
  --extapi-bc "$extapi" \
  --target-inst "{cand_str}" \
  --max-nodes 100000 \
  --max-edges 300000 \
  --output "$out/test_svfg.json" 2> "$out/test.err" || true

if [ -s "$out/test_svfg.json" ]; then
  grep "Resolved target instruction:" "$out/test.err" || true
fi
"""
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{ROOT_DIR}:/workspace",
        image, "bash", "-c", c_script,
    ]
    try:
        proc = subprocess.run(cmd, timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Check stderr or stdout for Resolved target instruction
        for line in proc.stdout.splitlines() + proc.stderr.splitlines():
            if "Resolved target instruction:" in line:
                return line.split("Resolved target instruction:", 1)[1].strip()
        # Fallback: read test_svfg.json target field
        test_json = ROOT_DIR / "cases" / case_id / "svf_backend" / "test_svfg.json"
        if test_json.is_file() and test_json.stat().st_size > 0:
            data = json.loads(test_json.read_text(encoding="utf-8"))
            tgt = data.get("target")
            if tgt:
                return tgt
        return None
    except subprocess.TimeoutExpired:
        return None


def find_candidate_instructions(case_dir: Path, oracle: Dict[str, Any]) -> List[str]:
    bb_map_path = case_dir / "bb_map.jsonl"
    before_path = case_dir / "svf_backend" / "before.jsonl"
    
    o_func = oracle.get("function", "")
    o_file = oracle.get("relative_source_file", "") or oracle.get("file", "")
    o_file_base = os.path.basename(o_file)
    o_line = oracle.get("line")

    # Tokenize o_func (split by non-alphanumeric, filtering short tokens)
    func_tokens = [tok for tok in re.split(r'[^a-zA-Z0-9]', o_func) if len(tok) >= 3 and tok.lower() not in ('zzip', 'get', 'set')]

    # 1. Read bb_map
    # bb_id -> {function, lines: set(), files: set()}
    bb_info: Dict[str, Dict[str, Any]] = {}
    with open(bb_map_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip(): continue
            rec = json.loads(line)
            bb_id = rec.get("bb_id")
            fn = rec.get("function", "")
            dlocs = rec.get("debug_locations", [])
            lines = set()
            files = set()
            for d in dlocs:
                if d.get("line"): lines.add(d["line"])
                if d.get("file"): files.add(os.path.basename(d["file"]))
            bb_info[bb_id] = {
                "function": fn,
                "lines": lines,
                "files": files,
            }

    # 2. Read before.jsonl: bb_id -> list of instructions
    bb_insts: Dict[str, List[Dict[str, Any]]] = {}
    with open(before_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip(): continue
            rec = json.loads(line)
            bb_id = rec.get("bb_id")
            bb_insts.setdefault(bb_id, []).append(rec)

    # 3. Score BBs
    scored_bbs: List[Tuple[int, str]] = []
    for bb_id, info in bb_info.items():
        if bb_id not in bb_insts:
            continue
        score = 0
        fn = info["function"]
        # Function matching
        if o_func and fn == o_func:
            score += 100
        elif any(tok in fn for tok in func_tokens):
            score += 40
        
        # File matching
        if o_file_base and any(o_file_base in f for f in info["files"]):
            score += 30
            
        # Line matching
        if o_line and o_line in info["lines"]:
            score += 50
        elif o_line and any(abs(l - o_line) <= 3 for l in info["lines"]):
            score += 20

        if score >= 40:
            scored_bbs.append((score, bb_id))

    # If any BB has score >= 100 (exact function match), filter out BBs that didn't match function
    max_score = max((s for s, _ in scored_bbs), default=0)
    if max_score >= 100:
        scored_bbs = [(s, b) for s, b in scored_bbs if s >= 100]

    scored_bbs.sort(key=lambda x: x[0], reverse=True)

    # Preferred opcodes for memory / value flow
    OPCODE_WEIGHT = {
        "load": 10,
        "store": 9,
        "getelementptr": 8,
        "call": 7,
        "invoke": 6,
        "phi": 5,
        "select": 4,
        "bitcast": 3,
        "icmp": 2,
    }

    candidates = []
    for _, bb_id in scored_bbs[:8]:
        insts = bb_insts.get(bb_id, [])
        scored_insts = []
        for inst in insts:
            op = inst.get("opcode", "")
            w = OPCODE_WEIGHT.get(op, 1)
            scored_insts.append((w, inst.get("id")))
        scored_insts.sort(key=lambda x: x[0], reverse=True)
        for _, inst_id in scored_insts:
            if inst_id:
                candidates.append(inst_id)

    if not candidates:
        fallback_bbs = []
        for bb_id, insts in bb_insts.items():
            if not insts:
                continue
            fn = insts[0].get("function", "")
            common = sum(1 for tok in func_tokens if tok.lower() in fn.lower())
            if common > 0:
                fallback_bbs.append((common, bb_id))
        fallback_bbs.sort(key=lambda x: x[0], reverse=True)
        for _, bb_id in fallback_bbs[:5]:
            insts = bb_insts.get(bb_id, [])
            for inst in insts:
                if inst.get("opcode") in ("load", "store", "getelementptr", "call"):
                    candidates.append(inst["id"])

    return candidates


def _execution_evidence(case: dict, case_dir: Path, bc_path: Path) -> tuple[set[str], str | None]:
    """Trust only the current direct BB trace, ASan and matching source/build hashes.

    The trace is needed for target calibration, not just for downstream labels.
    Old PC-symbolized traces or stale PoC/binary/BC outputs are not evidence.
    """
    from target_graph.tracing.evidence import asan_evidence, sha256
    trace_path = case_dir / "trace_bbs.json"
    run_path = case_dir / "trace_run.json"
    stderr_path = case_dir / "crash_stderr.txt"
    try:
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        run = json.loads(run_path.read_text(encoding="utf-8"))
        if trace.get("trace_mode") != "direct_bb_id" or trace.get("schema_version") != 2:
            return set(), "TRACE_NOT_DIRECT_BB_ID"
        if trace.get("case_id") != case["case_id"] or run.get("case_id") != case["case_id"]:
            return set(), "TRACE_CASE_ID_MISMATCH"
        bbs = trace.get("executed_bbs_unique")
        if not isinstance(bbs, list) or not bbs:
            return set(), "EMPTY_DIRECT_TRACE"
        checks = {
            "bitcode_sha256": bc_path,
            "instrumented_binary_sha256": case_dir / (case["target_binary"] + "_inst"),
            "poc_sha256": case_dir / "poc",
            "trace_file_sha256": case_dir / "trace_crash.txt",
        }
        for key, path in checks.items():
            if not path.is_file():
                return set(), f"MISSING_{key.upper()}"
            digest = sha256(path)
            if run.get(key) != digest or trace.get(key) != digest:
                return set(), f"STALE_{key.upper()}"
        bb_map_path = case_dir / "bb_map.jsonl"
        if trace.get("bb_map_sha256") != sha256(bb_map_path):
            return set(), "STALE_BB_MAP"
        stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
        if run.get("stderr_sha256") != sha256(stderr_path):
            return set(), "STALE_ASAN_STDERR"
        if run.get("poc_exit_code") == 0:
            return set(), "POC_DID_NOT_CRASH"
        if not asan_evidence(stderr, case.get("expected_oracle", {}))["crash_reproduced"]:
            return set(), "ASAN_ORACLE_FRAME_NOT_VERIFIED"
        source = case.get("expected_oracle", {})
        source_rel = str(source.get("relative_source_file") or "")
        if (not source_rel or source_rel.startswith("/") or
                ".." in Path(source_rel).parts):
            return set(), "INVALID_ORACLE_SOURCE_PATH"
        source_file = case_dir / "src" / source_rel
        if not source_file.is_file() or sha256(source_file) != source.get("source_file_sha256"):
            return set(), "ORACLE_SOURCE_SHA_MISMATCH"
        from target_graph.llvm.mapping import BasicBlockMapper
        mapper = BasicBlockMapper(bb_map_path)
        if not set(bbs).issubset(mapper.bb_records):
            return set(), "DIRECT_TRACE_BB_NOT_IN_GRAPH"
        return set(bbs), None
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as e:
        return set(), f"INVALID_EXECUTION_EVIDENCE: {e}"


def _approved_targets(path: Path) -> dict[str, dict]:
    """Explicit, reviewed target decisions; not auto-generated SVFG proposals."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("cases"), dict):
        raise ValueError("Approved targets file must contain a 'cases' object")
    approvals = raw["cases"]
    for case, record in approvals.items():
        if (not isinstance(record, dict) or
                not isinstance(record.get("target_inst"), str) or
                not record["target_inst"] or
                len(str(record.get("faulting_instruction_evidence") or "").strip()) < 12):
            raise ValueError(
                f"{case}: require target_inst and descriptive "
                "faulting_instruction_evidence (ASan PC/inline/operand review)"
            )
    return approvals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path,
                        default=ROOT_DIR / "configs/projects/benchmark_30_cases.yaml")
    parser.add_argument("--case", type=str, help="Calibrate single case")
    parser.add_argument("--apply", action="store_true",
                        help="Apply ONLY independently reviewed targets from --approved-targets")
    parser.add_argument("--approved-targets", type=Path,
                        help="JSON {cases:{case_id:{target_inst,faulting_instruction_evidence}}}")
    args = parser.parse_args()
    if args.apply and args.approved_targets is None:
        parser.error("--apply requires --approved-targets (no heuristic retargeting)")
    if args.approved_targets and not args.apply:
        parser.error("--approved-targets requires --apply")

    approvals = _approved_targets(args.approved_targets) if args.apply else {}
    with open(args.config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    cases = config.get("cases", [])
    if args.case:
        cases = [c for c in cases if c["case_id"] == args.case]
        if not cases:
            parser.error(f"Case {args.case} not present in {args.config}")
    if set(approvals) - {c["case_id"] for c in cases}:
        parser.error("Approved target file contains cases outside selected benchmark")

    if str(ROOT_DIR / "src") not in sys.path:
        sys.path.insert(0, str(ROOT_DIR / "src"))
    from target_graph.llvm.mapping import BasicBlockMapper
    from target_graph.tracing.target_resolution import inspect_target

    print(f"Auditing LLVM target identity for {len(cases)} cases...")
    results: list[dict] = []
    updates: dict[str, str] = {}
    rejected: list[str] = []

    for index, case in enumerate(cases, 1):
        cid = case["case_id"]
        cdir = ROOT_DIR / "cases" / cid
        old_target = str(case.get("canonical_target_inst") or "")
        result: dict[str, Any] = {
            "case_id": cid,
            "original_target": old_target,
            "svfg_compatible_proposal": None,
            "status": "NOT_ANALYZED",
            "applied": False,
            "approved_target": (approvals.get(cid) or {}).get("target_inst"),
        }
        try:
            bc_files = list(cdir.glob("*.bc"))
            if len(bc_files) != 1:
                raise ValueError(f"Expected exactly one original .bc, found {len(bc_files)}")
            bc = bc_files[0]
            build_id, module_name = get_canonical_provenance(cdir, bc.name)
            ensure_tagged_bc(cid, cdir, bc.name, build_id, module_name)
            direct_bbs, trace_error = _execution_evidence(case, cdir, bc)
            result["execution_evidence_status"] = trace_error or "VERIFIED_DIRECT_BB_ASAN"
            if trace_error:
                result["status"] = "NEEDS_EXECUTION_EVIDENCE"
                if cid in approvals:
                    rejected.append(cid + ": " + trace_error)
                continue

            mapper = BasicBlockMapper(cdir / "bb_map.jsonl")
            diagnostic = inspect_target(
                mapper.bb_records, direct_bbs, case.get("expected_oracle", {}),
                old_target, cdir / "svf_backend" / "before.jsonl",
                max_reported_instructions=8192,
            )
            result["identity_status"] = diagnostic["status"]
            result["original_target_executed"] = diagnostic["target_executed"]
            result["executed_oracle_bb_count"] = diagnostic["executed_oracle_bb_count"]
            result["executed_oracle_owner_functions"] = sorted({
                b["llvm_owner_function"] for b in diagnostic["candidate_owner_bbs"]
                if b["executed_in_direct_trace"]
            })

            # A candidate must be an instruction in an *exact* oracle-line BB
            # actually executed by the PoC. Broad function-token, +/-3 line
            # and arbitrary SVFG-first heuristics are no longer accepted.
            eligible = [inst["instruction_id"] for inst in diagnostic["candidate_instructions"]
                        if inst["source_line_candidate"] and
                        inst["executed_in_direct_trace"] and
                        inst["value_flow_relevant_opcode"]]
            eligible = list(dict.fromkeys(eligible))
            result["executed_oracle_instruction_candidates"] = eligible
            if not eligible:
                result["status"] = "NEEDS_ORACLE_TARGET_REVIEW"
                if cid in approvals:
                    rejected.append(cid + ": no exact executed oracle instruction candidates")
                continue

            proposed = test_target_candidates(cid, eligible[:64])
            if proposed not in eligible:
                proposed = None
            result["svfg_compatible_proposal"] = proposed
            result["status"] = "PROPOSAL_ONLY_REQUIRES_REVIEW"
            if cid not in approvals:
                continue

            manually_approved = approvals[cid]["target_inst"]
            if manually_approved not in eligible:
                rejected.append(cid + ": approved target not in exact executed oracle candidates")
                continue
            if test_target_candidates(cid, [manually_approved]) != manually_approved:
                rejected.append(cid + ": approved target did not pass native SVFG mapping")
                continue
            updates[cid] = manually_approved
            result["status"] = "REVIEWED_TARGET_ACCEPTED"
            result["applied"] = bool(args.apply)
            print(f"[{index:02d}/{len(cases):02d}] {cid}: reviewed {manually_approved}")
        except Exception as exc:
            result["status"] = "ANALYSIS_FAILED"
            result["error"] = str(exc)
            if cid in approvals:
                rejected.append(cid + ": " + str(exc))
        finally:
            result_path = cdir / "target_calibration.json"
            result_path.parent.mkdir(parents=True, exist_ok=True)
            result_path.write_text(
                json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            results.append(result)
            if result["status"] not in {"REVIEWED_TARGET_ACCEPTED"}:
                print(f"[{index:02d}/{len(cases):02d}] {cid}: {result['status']} "
                      f"({result.get('identity_status', '')})")

    if args.apply:
        if rejected or set(updates) != set(approvals):
            print("Refusing ALL YAML changes due to invalid manual approvals:", file=sys.stderr)
            for item in rejected:
                print("  " + item, file=sys.stderr)
            sys.exit(1)
        if updates:
            for entry in config["cases"]:
                if entry["case_id"] in updates:
                    entry["canonical_target_inst"] = updates[entry["case_id"]]
            tmp = args.config.with_name(args.config.name + ".tmp")
            tmp.write_text(
                yaml.safe_dump(config, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
            tmp.replace(args.config)
            print(f"Applied {len(updates)} explicitly reviewed targets to {args.config}")

    print(f"Target audit completed: {len(results)} cases. "
          "No automatically selected target was applied.")


if __name__ == "__main__":
    main()

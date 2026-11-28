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
    del case_id, bc_name, build_id, module_name, image
    inst_map = case_dir / "inst_map.jsonl"
    if not inst_map.is_file() and not (case_dir / "svf_backend" / "before.jsonl").is_file():
        raise FileNotFoundError(f"Missing inst_map.jsonl in {case_dir}; rebuild with bb-tag")


def test_target_candidates(
    case_id: str,
    candidates: List[str],
    image: str = "target-graph:svf-llvm14",
    timeout: int = 120,
    probe_details: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Probe ONE SVFG for all candidates, fail closed on native errors.

    The native backend chooses the first *value-flow-representable* seed,
    NOT necessarily the faulting instruction. Save seed counts for ALL
    candidates; the caller must independently review the faulting operand.
    """
    details = probe_details if probe_details is not None else {}
    details.clear()
    details["requested_candidates"] = list(candidates)
    details["status"] = "NOT_RUN"
    if not candidates:
        details["status"] = "NO_CANDIDATES"
        return None
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+", case_id) or not all(
        re.fullmatch(r"[0-9a-f]{16}:[0-9]+", cand) for cand in candidates
    ):
        details["status"] = "INVALID_CASE_OR_INSTRUCTION_ID"
        return None

    out_dir = ROOT_DIR / "cases" / case_id / "svf_backend"
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / "test_svfg.json"
    # Remove stale output BEFORE starting Docker, not just from inside it.
    raw_path.unlink(missing_ok=True)
    (out_dir / "test.err").unlink(missing_ok=True)
    cand_str = ",".join(candidates)
    c_script = f"""
set -euo pipefail
out="/workspace/cases/{case_id}/svf_backend"
extapi="/opt/SVF/Release-build/svf-llvm/extapi.bc"
bc=( /workspace/cases/{case_id}/*.bc )
targetgraph-svf \\
  --input "${{bc[0]}}" \\
  --extapi-bc "$extapi" \\
  --target-inst "{cand_str}" \\
  --max-nodes 100000 \\
  --max-edges 300000 \\
  --output "$out/test_svfg.json" 2> "$out/test.err"
"""
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{ROOT_DIR}:/workspace",
        image, "bash", "-c", c_script,
    ]
    try:
        proc = subprocess.run(
            cmd, timeout=timeout, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, check=False
        )
    except subprocess.TimeoutExpired:
        details["status"] = "NATIVE_PROBE_TIMEOUT"
        return None
    except OSError as exc:
        details["status"] = "DOCKER_INVOCATION_FAILED"
        details["error"] = str(exc)
        return None

    details["native_exit_code"] = proc.returncode
    if proc.returncode != 0:
        details["status"] = "NATIVE_PROBE_FAILED"
        # The native stderr may contain a precise traversal-budget reason.
        native_err = out_dir / "test.err"
        if native_err.is_file():
            details["native_error_tail"] = native_err.read_text(
                encoding="utf-8", errors="replace"
            )[-1000:]
        return None
    if not raw_path.is_file():
        details["status"] = "NATIVE_REPORT_MISSING"
        return None

    try:
        data = json.loads(raw_path.read_text(encoding="utf-8"))
        if (not isinstance(data, dict) or
                data.get("backend") != "SVF-2.9/SVFG" or
                data.get("analysis") != "BACKWARD_VALUE_FLOW_ONLY" or
                data.get("status") != "EXPLORATORY_ONLY"):
            raise ValueError("invalid SVFG report schema")
        selected = data.get("target")
        if not isinstance(selected, str) or selected not in candidates:
            raise ValueError("resolved target is not among submitted candidates")

        # A genuinely successful native analysis must carry complete
        # candidate seed counts from the SAME SVFG construction.
        counters = data.get("candidate_seed_counts")
        if not isinstance(counters, list) or len(counters) != len(candidates):
            raise ValueError(
                "missing candidate_seed_counts; rebuild target-graph:svf-llvm14"
            )
        positive = []
        for expected, row in zip(candidates, counters):
            if (not isinstance(row, dict) or
                    row.get("instruction_id") != expected or
                    type(row.get("svfg_seed_count")) is not int or
                    row["svfg_seed_count"] < 0):
                raise ValueError("invalid or reordered candidate seed counts")
            if row["svfg_seed_count"] > 0:
                positive.append(expected)
        if not positive or selected != positive[0]:
            raise ValueError("selected target is not the first SVFG-compatible candidate")

        seeds = data.get("target_seed_svfg_ids")
        nodes = data.get("svfg_nodes")
        if not isinstance(seeds, list) or not seeds or not isinstance(nodes, list):
            raise ValueError("missing SVFG seed evidence")
        by_node = {node.get("svfg_id"): node.get("instruction_id")
                   for node in nodes if isinstance(node, dict)}
        if any(type(seed) is not int or by_node.get(seed) != selected for seed in seeds):
            raise ValueError("selected target seeds do not match mapped LLVM IDs")
        if len(seeds) != counters[candidates.index(selected)]["svfg_seed_count"]:
            raise ValueError("selected seed count differs from native SVFG evidence")

        details["status"] = "SVFG_PROBE_COMPLETE_EXPLORATORY_ONLY"
        details["selected_target"] = selected
        details["candidate_seed_counts"] = counters
        details["svfg_compatible_candidates"] = positive
        details["warning"] = (
            "Seed existence indicates value-flow representation only; "
            "it does not verify the faulting memory operand."
        )
        return selected
    except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
        details["status"] = "NATIVE_REPORT_INVALID"
        details["error"] = str(exc)
        return None


def review_memory_access_candidates(
    instruction_evidence: List[Dict[str, Any]],
    probe: Dict[str, Any],
) -> Dict[str, Any]:
    """Prioritize faulting *memory access* review, never approve a target.

    A getelementptr is pure pointer computation. Load/store/atomic operations
    can dereference memory, but a BB-entry trace and SVFG seed count do NOT
    establish that a given instruction faulted or even executed.
    """
    compatible = set(probe.get("svfg_compatible_candidates") or [])
    by_id = {
        row.get("instruction_id"): row for row in instruction_evidence
        if isinstance(row, dict) and isinstance(row.get("instruction_id"), str)
    }
    memory = [
        inst_id for inst_id, row in by_id.items()
        if inst_id in compatible and row.get("fault_site_role") == "DIRECT_MEMORY_ACCESS"
    ]
    other = [
        inst_id for inst_id in probe.get("svfg_compatible_candidates", [])
        if inst_id in by_id and inst_id not in memory
    ]
    result = {
        "memory_access_review_candidates": memory,
        "other_value_flow_review_candidates": other,
        "manual_review_order": memory + other,
        "requires_fault_pc_operand_verification": True,
        "memory_access_priority_is_not_ground_truth": True,
    }
    if len(memory) == 1:
        result["single_memory_access_hypothesis"] = memory[0]
    else:
        result["single_memory_access_hypothesis"] = None
    return result


def find_candidate_instructions(case_dir: Path, oracle: Dict[str, Any]) -> List[str]:
    bb_map_path = case_dir / "bb_map.jsonl"
    before_path = case_dir / "inst_map.jsonl"
    if not before_path.is_file():
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
        if (type(run.get("poc_exit_code")) is not int or
                run["poc_exit_code"] == 0):
            return set(), "POC_EXIT_CODE_UNVERIFIED"
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
            # Fail fast on an incorrect PoC/ASan/trace before paying for
            # LLVM tagging or SVFG graph construction.
            direct_bbs, trace_error = _execution_evidence(case, cdir, bc)
            result["execution_evidence_status"] = trace_error or "VERIFIED_DIRECT_BB_ASAN"
            if trace_error:
                result["status"] = "NEEDS_EXECUTION_EVIDENCE"
                if cid in approvals:
                    rejected.append(cid + ": " + trace_error)
                continue

            ensure_tagged_bc(cid, cdir, bc.name, build_id, module_name)
            mapper = BasicBlockMapper(cdir / "bb_map.jsonl")
            inst_map_path = cdir / "inst_map.jsonl"
            if not inst_map_path.is_file():
                inst_map_path = cdir / "svf_backend" / "before.jsonl"
            diagnostic = inspect_target(
                mapper.bb_records, direct_bbs, case.get("expected_oracle", {}),
                old_target, inst_map_path,
                v2_nodes_path=cdir / "analysis_v2_nodes.jsonl",
                max_reported_instructions=8192,
            )
            result["identity_status"] = diagnostic["status"]
            result["original_target_executed"] = diagnostic["target_executed"]
            result["executed_oracle_bb_count"] = diagnostic["executed_oracle_bb_count"]
            result["executed_oracle_owner_functions"] = sorted({
                b["llvm_owner_function"] for b in diagnostic["candidate_owner_bbs"]
                if b["executed_in_direct_trace"]
            })

            # BB-level DebugLoc is a union of its instructions' locations.
            # Require the *specific instruction's* V2 DebugLoc + identity
            # to match, rather than every load/store within a matching BB.
            # Never fall back to arbitrary BB membership or nearest line.
            result["v2_metadata_status"] = diagnostic["inline_metadata_status"]
            result["exact_oracle_instruction_debugloc_matches"] = (
                diagnostic["exact_oracle_instruction_debugloc_matches"]
            )
            eligible_rows = [inst for inst in diagnostic["candidate_instructions"]
                             if isinstance(inst.get("instruction_id"), str) and
                             inst.get("v2_instruction_identity_verified") is True and
                             inst.get("instruction_exact_oracle_source_line") is True and
                             inst["executed_in_direct_trace"] and
                             inst["value_flow_relevant_opcode"]]
            eligible = list(dict.fromkeys(
                inst["instruction_id"] for inst in eligible_rows
            ))
            result["executed_oracle_instruction_candidates"] = eligible
            memory_ops = {"load", "store", "atomicrmw", "cmpxchg"}
            result["candidate_instruction_evidence"] = [
                {
                    "instruction_id": inst["instruction_id"],
                    "opcode": inst["opcode"],
                    "fault_site_role": (
                        "DIRECT_MEMORY_ACCESS" if inst["opcode"] in memory_ops
                        else "ADDRESS_COMPUTATION" if inst["opcode"] == "getelementptr"
                        else "OTHER_VALUE_FLOW"
                    ),
                    "inline_callsite_chain": inst.get("inline_callsite_chain"),
                    "llvm_owner_function": inst.get("llvm_owner_function"),
                    "instruction_source_file": inst.get("instruction_source_file"),
                    "instruction_line": inst.get("instruction_line"),
                }
                for inst in eligible_rows
            ]
            if not eligible:
                result["status"] = (
                    "NEEDS_V2_INSTRUCTION_DEBUGLOC"
                    if diagnostic["inline_metadata_status"] in {
                        "V2_NODES_NOT_AVAILABLE",
                        "V2_IDS_NOT_ALIGNED_OR_STALE",
                    } else "NEEDS_ORACLE_TARGET_REVIEW"
                )
                if cid in approvals:
                    rejected.append(cid + ": no exact executed oracle instruction candidates")
                continue

            probe_details: Dict[str, Any] = {}
            proposed = test_target_candidates(
                cid, eligible[:64], probe_details=probe_details
            )
            result["svfg_candidate_probe"] = probe_details
            result["candidate_probe_truncated"] = len(eligible) > 64
            if proposed not in eligible or (
                probe_details.get("status") != "SVFG_PROBE_COMPLETE_EXPLORATORY_ONLY"
            ):
                proposed = None
            result["svfg_compatible_proposal"] = proposed
            if proposed is None:
                result["status"] = "SVFG_PROBE_INCOMPLETE"
                if cid in approvals:
                    rejected.append(cid + ": " + probe_details.get("status", "UNKNOWN"))
                continue
            by_id = {row["instruction_id"]: row
                     for row in result["candidate_instruction_evidence"]}
            chosen_role = by_id[proposed]["fault_site_role"]
            result["selected_proposal_role"] = chosen_role
            direct_memory_alternatives = [
                inst for inst in eligible if
                by_id[inst]["fault_site_role"] == "DIRECT_MEMORY_ACCESS"
                and inst != proposed
            ]
            result["direct_memory_access_alternatives"] = direct_memory_alternatives
            result["faulting_access_review"] = review_memory_access_candidates(
                result["candidate_instruction_evidence"], probe_details
            )
            if chosen_role == "ADDRESS_COMPUTATION" and direct_memory_alternatives:
                result["candidate_review_warning"] = (
                    "FIRST_SVFG_SEED_IS_GEP_BUT_POC_EXECUTED_DIRECT_MEMORY_ACCESS"
                )
            result["status"] = "PROPOSAL_ONLY_REQUIRES_REVIEW"
            if cid not in approvals:
                continue

            manually_approved = approvals[cid]["target_inst"]
            if manually_approved not in eligible:
                rejected.append(cid + ": approved target not in exact executed oracle candidates")
                continue
            approved_probe: Dict[str, Any] = {}
            approved_match = test_target_candidates(
                cid, [manually_approved], probe_details=approved_probe
            )
            result["approved_target_probe"] = approved_probe
            if (approved_match != manually_approved or
                    approved_probe.get("status") !=
                    "SVFG_PROBE_COMPLETE_EXPLORATORY_ONLY"):
                rejected.append(
                    cid + ": approved target native SVFG probe failed: " +
                    approved_probe.get("status", "UNKNOWN")
                )
                continue
            updates[cid] = manually_approved
            result["status"] = "REVIEWED_TARGET_ACCEPTED"
            # Record approval separately; YAML is committed atomically only
            # after ALL reviewed candidates are accepted.
            result["applied"] = False
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
            for approved_case in updates:
                report_path = ROOT_DIR / "cases" / approved_case / "target_calibration.json"
                report = json.loads(report_path.read_text(encoding="utf-8"))
                report["applied"] = True
                report["status"] = "REVIEWED_TARGET_APPLIED"
                report_path.write_text(
                    json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
            print(f"Applied {len(updates)} explicitly reviewed targets to {args.config}")

    print(f"Target audit completed: {len(results)} cases. "
          "No automatically selected target was applied.")


if __name__ == "__main__":
    main()

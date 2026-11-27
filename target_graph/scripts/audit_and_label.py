#!/usr/bin/env python3
"""audit_and_label.py - Verify trace_bbs against expected_oracle and generate svf_weak_labels.json.

Pipeline per case:
1. Read cases/<case_id>/trace_bbs.json.
2. Map expected_oracle (and canonical_target_inst) via bb_map.jsonl.
3. Verify trace_bbs hits expected_oracle.
4. Write cases/<case_id>/audit.json (status: PASSED or FAILED).
5. Only if PASSED and svf_backend/svf_slice.json exists, compute the pure intersection
   S_SVF(t) & E_t and write cases/<case_id>/svf_weak_labels.json.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR / "src") not in sys.path:
    sys.path.insert(0, str(ROOT_DIR / "src"))

from target_graph.llvm.mapping import BasicBlockMapper
from target_graph.tracing.evidence import asan_evidence, sha256
from target_graph.tracing.target_resolution import inspect_target


def audit_and_label_case(case_meta: Dict[str, Any], cases_dir: Path) -> Dict[str, Any]:
    """Fail-closed audit of real crash, direct BB execution and SVF provenance.

    PASSED means an *eligible weak-label candidate*, NOT verified root-cause
    localization. Nonpositive BBs are UNKNOWN, never verified negatives.
    """
    cid = case_meta["case_id"]
    cdir = cases_dir / cid
    oracle = case_meta.get("expected_oracle", {})
    target_inst = case_meta.get("canonical_target_inst", "")
    target_bb = target_inst.split(":")[0] if ":" in target_inst else ""

    trace_path = cdir / "trace_bbs.json"
    trace_run_path = cdir / "trace_run.json"
    stderr_path = cdir / "crash_stderr.txt"
    bb_map_path = cdir / "bb_map.jsonl"
    svf_path = cdir / "svf_backend" / "svf_slice.json"
    audit_path = cdir / "audit.json"
    labels_path = cdir / "svf_weak_labels.json"
    target_diagnostics_path = cdir / "target_diagnostics.json"

    # A failed rerun must never leave the previous label in place.
    labels_path.unlink(missing_ok=True)
    target_diagnostics_path.unlink(missing_ok=True)
    record: Dict[str, Any] = {
        "case_id": cid,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "expected_oracle": oracle,
        "target_inst": target_inst,
        "target_bb": target_bb,
        "oracle_bbs": [],
        "oracle_hit_bbs": [],
        "oracle_hit": False,
        "target_bb_hit": False,
        "target_in_graph": False,
        "target_in_original_ir": None,
        "target_resolution_status": None,
        "executed_oracle_bb_count": 0,
        "has_trace_bbs": trace_path.is_file(),
        "has_svf_slice": svf_path.is_file(),
        "trace_mode": None,
        "crash_reproduced": False,
        "source_sha_verified": False,
        "bitcode_sha_verified": False,
        "status": "FAILED",
        "failure_reason": None,
        "num_trace_bbs": 0,
        "num_svf_slice_bbs": 0,
        "num_weak_positive_bbs": 0,
        "label_quality": "UNVERIFIED",
    }

    def _fail(reason: str) -> Dict[str, Any]:
        record["status"] = "FAILED"
        record["failure_reason"] = reason
        audit_path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return record

    if not trace_path.is_file():
        return _fail("MISSING_TRACE_BBS")
    if not trace_run_path.is_file() or not stderr_path.is_file():
        return _fail("MISSING_CRASH_EVIDENCE")
    if not bb_map_path.is_file():
        return _fail("MISSING_BB_MAP")
    if not target_bb:
        return _fail("MISSING_CANONICAL_TARGET")

    try:
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        run = json.loads(trace_run_path.read_text(encoding="utf-8"))
        if trace.get("case_id") != cid or run.get("case_id") != cid:
            return _fail("TRACE_CASE_ID_MISMATCH")
        record["trace_mode"] = trace.get("trace_mode")
        if trace.get("trace_mode") != "direct_bb_id" or trace.get("schema_version") != 2:
            return _fail("TRACE_NOT_DIRECT_BB_ID")
        trace_list = trace.get("executed_bbs_unique")
        if not isinstance(trace_list, list) or not trace_list:
            return _fail("EMPTY_DIRECT_TRACE")
        trace_bbs = set(trace_list)
        if len(trace_bbs) != len(trace_list):
            return _fail("DUPLICATE_UNIQUE_TRACE_BBS")
        mapper = BasicBlockMapper(bb_map_path)
        if not trace_bbs.issubset(mapper.bb_records):
            return _fail("TRACE_BBS_NOT_IN_GRAPH")
        record["num_trace_bbs"] = len(trace_bbs)

        target_bin = case_meta["target_binary"]
        bc_path = cdir / (target_bin + ".bc")
        bin_path = cdir / (target_bin + "_inst")
        poc_path = cdir / "poc"
        trace_raw_path = cdir / "trace_crash.txt"
        required = {
            "instrumented_binary_sha256": bin_path,
            "poc_sha256": poc_path,
            "bitcode_sha256": bc_path,
            "trace_file_sha256": trace_raw_path,
        }
        for key, path in required.items():
            if not path.is_file():
                return _fail("MISSING_ARTIFACT_" + key.upper())
            digest = sha256(path)
            if trace.get(key) != digest or run.get(key) != digest:
                return _fail("TRACE_ARTIFACT_HASH_MISMATCH_" + key.upper())
        if trace.get("bb_map_sha256") != sha256(bb_map_path):
            return _fail("TRACE_BB_MAP_HASH_MISMATCH")

        stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
        if run.get("stderr_sha256") != sha256(stderr_path):
            return _fail("TRACE_STDERR_HASH_MISMATCH")
        evidence = asan_evidence(stderr_text, oracle)
        record["crash_reproduced"] = evidence["crash_reproduced"]
        record["asan_evidence"] = evidence
        # Record all exact DebugLoc owners before applying either ASan or
        # SVF gates. A stale target cannot hide behind an ASan frame mismatch.
        diagnostic = inspect_target(
            mapper.bb_records, trace_bbs, oracle, target_inst,
            cdir / "svf_backend" / "before.jsonl",
        )
        target_diagnostics_path.write_text(
            json.dumps(diagnostic, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        record["target_in_graph"] = diagnostic["target_in_graph"]
        record["target_in_original_ir"] = diagnostic["target_in_original_ir"]
        record["target_resolution_status"] = diagnostic["status"]
        record["target_bb_hit"] = diagnostic["target_executed"]
        record["oracle_bbs"] = diagnostic["oracle_bbs"]
        record["oracle_hit_bbs"] = diagnostic["executed_oracle_bbs"]
        record["oracle_hit"] = bool(diagnostic["executed_oracle_bbs"])
        record["executed_oracle_bb_count"] = diagnostic["executed_oracle_bb_count"]
        if diagnostic["status"] in {
            "TARGET_NOT_IN_CURRENT_GRAPH",
            "TARGET_NOT_IN_CURRENT_IR",
            "MISSING_ORIGINAL_INST_MAP",
        }:
            return _fail(diagnostic["status"])

        if not isinstance(run.get("poc_exit_code"), int) or run["poc_exit_code"] == 0:
            return _fail("POC_DID_NOT_FAIL")
        if not evidence["crash_reproduced"]:
            return _fail("ASAN_ORACLE_NOT_REPRODUCED")

        source_rel = str(oracle.get("relative_source_file") or "")
        source_sha = str(oracle.get("source_file_sha256") or "")
        if not source_rel or source_rel.startswith("/") or ".." in Path(source_rel).parts:
            return _fail("INVALID_ORACLE_SOURCE_PATH")
        source_path = cdir / "src" / source_rel
        if not source_path.is_file() or not source_sha:
            return _fail("MISSING_ORACLE_SOURCE")
        if sha256(source_path).lower() != source_sha.lower():
            return _fail("SOURCE_PROVENANCE_HASH_MISMATCH")
        record["source_sha_verified"] = True

        # Mapping was computed from exact, normalized DebugLoc paths and
        # recorded in target_diagnostics.json, without any line fallback.
        oracle_bbs = record["oracle_bbs"]
        if not oracle_bbs:
            return _fail("ORACLE_NOT_EXACTLY_MAPPED_IN_BB_MAP")
        if not record["oracle_hit"]:
            return _fail("ORACLE_NOT_HIT_IN_DIRECT_TRACE")
        if not record["target_bb_hit"]:
            return _fail("TARGET_BB_NOT_HIT_IN_DIRECT_TRACE")
        if not svf_path.is_file():
            return _fail("MISSING_SVF_SLICE")
        svf = json.loads(svf_path.read_text(encoding="utf-8"))
        if (svf.get("backend") != "SVF-2.9/SVFG" or
                svf.get("analysis") != "BACKWARD_VALUE_FLOW_ONLY" or
                svf.get("status") != "EXPLORATORY_ONLY" or
                svf.get("validated_for_supervision") is not False):
            return _fail("INVALID_SVF_EVIDENCE_SCHEMA")
        if svf.get("original_bitcode_sha256") != sha256(bc_path):
            return _fail("SVF_BITCODE_HASH_MISMATCH")
        record["bitcode_sha_verified"] = True
        if svf.get("target") != target_inst or target_inst not in svf.get("instruction_ids", []):
            return _fail("SVF_TARGET_MISMATCH")
        svf_bbs = set(svf.get("basic_blocks", []))
        record["num_svf_slice_bbs"] = len(svf_bbs)
        if not svf_bbs.issubset(mapper.bb_records):
            return _fail("SVF_BBS_NOT_IN_GRAPH")
        if target_bb not in svf_bbs:
            return _fail("SVF_TARGET_BB_MISSING")
        positives = sorted(svf_bbs & trace_bbs)
        record["num_weak_positive_bbs"] = len(positives)
        if not positives:
            return _fail("EMPTY_SVF_TRACE_INTERSECTION")

        # This is STILL candidate weak supervision. SVF may-alias edges and
        # absent CDG/call context do not constitute verified vulnerability labels.
        record["status"] = "PASSED"
        record["label_quality"] = "CANDIDATE_WEAK_POSITIVES_ONLY"
        audit_path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        labels = {
            "schema_version": 2,
            "case_id": cid,
            "label_method": "SVF_BACKWARD_VALUE_FLOW_INTERSECT_DIRECT_POC_BB_TRACE",
            "supervision_validated": False,
            "verified_negative_bbs": [],
            "unlisted_bbs_are": "UNKNOWN",
            "target_inst": target_inst,
            "target_bb": target_bb,
            "oracle_bbs": oracle_bbs,
            "oracle_hit_bbs": record["oracle_hit_bbs"],
            "original_bitcode_sha256": sha256(bc_path),
            "trace_file_sha256": sha256(trace_raw_path),
            "num_trace_bbs": len(trace_bbs),
            "num_svf_slice_bbs": len(svf_bbs),
            "num_weak_positive_bbs": len(positives),
            "retention_over_trace": round(len(positives) / len(trace_bbs), 6),
            "retention_over_svf": round(len(positives) / len(svf_bbs), 6),
            "weak_positive_bbs": positives,
        }
        labels_path.write_text(json.dumps(labels, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return record
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        return _fail("AUDIT_INPUT_INVALID: " + str(exc)[:240])


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
        "--output-dir",
        type=Path,
        default=ROOT_DIR / "reports/weak_labels_audit",
        help="Directory to write overall audit summary",
    )
    parser.add_argument(
        "--case",
        type=str,
        help="Run for a single case ID",
    )
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        cases = yaml.safe_load(f).get("cases", [])

    if args.case:
        cases = [c for c in cases if c["case_id"] == args.case]
        if not cases:
            print(f"Error: case {args.case} not found", file=sys.stderr)
            sys.exit(1)

    records: List[Dict[str, Any]] = []
    passed = 0
    for c in cases:
        rec = audit_and_label_case(c, args.cases_dir)
        records.append(rec)
        cid = rec["case_id"]
        if rec["status"] == "PASSED":
            passed += 1
            print(
                f"[PASS] {cid}: trace_bbs={rec['num_trace_bbs']}, "
                f"svf_bbs={rec['num_svf_slice_bbs']}, "
                f"intersection={rec['num_weak_positive_bbs']}"
            )
        else:
            print(f"[FAIL] {cid}: reason={rec['failure_reason']} (trace_bbs={rec['num_trace_bbs']}, target_hit={rec['target_bb_hit']})")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary_payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_cases": len(records),
        "passed_cases": passed,
        "failed_cases": len(records) - passed,
        "records": records,
    }
    (args.output_dir / "audit_summary.json").write_text(
        json.dumps(summary_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"\nAudit Summary: {passed}/{len(records)} PASSED.")


if __name__ == "__main__":
    main()

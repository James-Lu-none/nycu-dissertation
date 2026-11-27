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


def audit_and_label_case(case_meta: Dict[str, Any], cases_dir: Path) -> Dict[str, Any]:
    cid = case_meta["case_id"]
    cdir = cases_dir / cid
    oracle = case_meta.get("expected_oracle", {})
    target_inst = case_meta.get("canonical_target_inst", "")
    target_bb = target_inst.split(":")[0] if ":" in target_inst else ""

    trace_bbs_path = cdir / "trace_bbs.json"
    bb_map_path = cdir / "bb_map.jsonl"
    svf_slice_path = cdir / "svf_backend" / "svf_slice.json"
    audit_path = cdir / "audit.json"
    labels_path = cdir / "svf_weak_labels.json"

    audit_record: Dict[str, Any] = {
        "case_id": cid,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "expected_oracle": oracle,
        "target_inst": target_inst,
        "target_bb": target_bb,
        "oracle_bbs": [],
        "oracle_hit_bbs": [],
        "oracle_hit": False,
        "target_bb_hit": False,
        "has_trace_bbs": trace_bbs_path.is_file(),
        "has_svf_slice": svf_slice_path.is_file(),
        "status": "FAILED",
        "failure_reason": None,
        "num_trace_bbs": 0,
        "num_svf_slice_bbs": 0,
        "num_weak_positive_bbs": 0,
    }

    def _fail(reason: str) -> Dict[str, Any]:
        audit_record["status"] = "FAILED"
        audit_record["failure_reason"] = reason
        audit_path.write_text(json.dumps(audit_record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if labels_path.exists():
            labels_path.unlink()
        return audit_record

    if not trace_bbs_path.is_file():
        return _fail("MISSING_TRACE_BBS")
    if not bb_map_path.is_file():
        return _fail("MISSING_BB_MAP")

    trace_data = json.loads(trace_bbs_path.read_text(encoding="utf-8"))
    trace_bbs_list: List[str] = trace_data.get("executed_bbs_unique", [])
    trace_bbs_set: Set[str] = set(trace_bbs_list)
    audit_record["num_trace_bbs"] = len(trace_bbs_set)

    mapper = BasicBlockMapper(bb_map_path)
    oracle_file = oracle.get("relative_source_file", "")
    oracle_line = int(oracle.get("line", 0) or 0)
    oracle_func = oracle.get("function") or None

    oracle_bbs_func = mapper.map_source_location(oracle_file, oracle_line, function_name=oracle_func)
    oracle_bbs_all = mapper.map_source_location(oracle_file, oracle_line)
    # Include both exact-function BBs and inlined copies at the same source file/line
    oracle_bbs = list(dict.fromkeys([*oracle_bbs_func, *oracle_bbs_all]))

    audit_record["oracle_bbs"] = oracle_bbs
    oracle_hit_bbs = [b for b in oracle_bbs if b in trace_bbs_set]
    audit_record["oracle_hit_bbs"] = oracle_hit_bbs
    audit_record["oracle_hit"] = len(oracle_hit_bbs) > 0
    audit_record["target_bb_hit"] = bool(target_bb and target_bb in trace_bbs_set)

    if not audit_record["oracle_hit"]:
        if not oracle_bbs:
            return _fail("ORACLE_LOCATION_UNMAPPED_IN_BB_MAP")
        return _fail("ORACLE_NOT_HIT_IN_TRACE")

    if not svf_slice_path.is_file():
        return _fail("MISSING_SVF_SLICE")

    svf_data = json.loads(svf_slice_path.read_text(encoding="utf-8"))
    svf_bbs_list: List[str] = svf_data.get("basic_blocks", [])
    svf_bbs_set: Set[str] = set(svf_bbs_list)
    audit_record["num_svf_slice_bbs"] = len(svf_bbs_set)

    # Pure intersection: S_SVF(t) & E_t
    weak_positive_bbs = sorted(svf_bbs_set & trace_bbs_set)
    audit_record["num_weak_positive_bbs"] = len(weak_positive_bbs)
    audit_record["status"] = "PASSED"
    audit_record["failure_reason"] = None

    audit_path.write_text(json.dumps(audit_record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    retention_trace = round(len(weak_positive_bbs) / len(trace_bbs_set), 6) if trace_bbs_set else 0.0
    retention_svf = round(len(weak_positive_bbs) / len(svf_bbs_set), 6) if svf_bbs_set else 0.0

    labels_payload = {
        "schema_version": 1,
        "case_id": cid,
        "label_method": "SVF_BACKWARD_SLICE_INTERSECT_POC_TRACE",
        "target_inst": target_inst,
        "target_bb": target_bb,
        "oracle_bbs": oracle_bbs,
        "oracle_hit_bbs": oracle_hit_bbs,
        "num_trace_bbs": len(trace_bbs_set),
        "num_svf_slice_bbs": len(svf_bbs_set),
        "num_weak_positive_bbs": len(weak_positive_bbs),
        "retention_over_trace": retention_trace,
        "retention_over_svf": retention_svf,
        "weak_positive_bbs": weak_positive_bbs,
    }
    labels_path.write_text(json.dumps(labels_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return audit_record


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

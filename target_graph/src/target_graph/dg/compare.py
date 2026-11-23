"""Diagnostic comparison of the existing v2 slice and DG slice.

A difference is NOT proof of a defect in either analysis: DG includes memory
dependencies that the partial v2 SSA flow does not, and DG criteria can match
multiple source sites.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from target_graph.analysis_v2.graph import DependencyGraph
from target_graph.analysis_v2.slicing import backward_slice


def compare(case_dir: Path, dg_output: Path, target_inst: str) -> dict:
    dg = json.loads(dg_output.read_text(encoding="utf-8"))
    if dg.get("backend") != "DG/llvm-slicer" or dg.get("target") != target_inst:
        raise ValueError("DG result backend or target instruction mismatch")
    if dg.get("validated_for_supervision") is not False:
        raise ValueError("Unexpected training-supervision claim in DG data")
    graph = DependencyGraph.from_directory(case_dir)
    old = backward_slice(graph, target_inst)
    a, b = set(dg["basic_blocks"]), old.basic_blocks
    if not a or not b:
        raise ValueError("Cannot compare empty BB sets")
    return {
        "target": target_inst,
        "dg_backend": dg["backend"],
        "analysis_v2_status": "PARTIAL_STATIC_VALUE_FLOW",
        "validated_for_supervision": False,
        "jaccard": len(a & b) / len(a | b),
        "dg_only_bbs": sorted(a - b),
        "v2_only_bbs": sorted(b - a),
        "shared_bbs": len(a & b),
        "dg_bbs": len(a),
        "v2_bbs": len(b),
        "v2_unknown_boundaries": old.unknown_boundaries,
        "v2_truncated": old.truncated,
        "warning": "Differences may be due to analysis precision or criterion mismatch.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-dir", type=Path, required=True)
    parser.add_argument("--dg-output", type=Path)
    parser.add_argument("--target-inst", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = compare(
        args.case_dir, args.dg_output or args.case_dir / "dg_backend/dg_slice.json",
        args.target_inst
    )
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()

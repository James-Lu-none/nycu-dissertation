"""Compare SVF value-flow BB candidates to existing analysis-v2 diagnostics.

Differences reflect distinct analysis semantics; they do not prove either
analysis is more correct. SVF here excludes full control dependence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from target_graph.analysis_v2.graph import DependencyGraph
from target_graph.analysis_v2.slicing import backward_slice


def compare(case_dir: Path, svf_report: Path, target_inst: str) -> dict:
    s = json.loads(svf_report.read_text(encoding="utf-8"))
    if s.get("backend") != "SVF-2.9/SVFG" or s.get("target") != target_inst:
        raise ValueError("SVF backend or target instruction mismatch")
    if s.get("validated_for_supervision") is not False:
        raise ValueError("Unexpected SVF training-supervision claim")
    a = set(s.get("basic_blocks", []))
    if not a:
        raise ValueError("Empty SVF BB candidate set")
    graph = DependencyGraph.from_directory(case_dir)
    old = backward_slice(graph, target_inst)
    b = old.basic_blocks
    if not b:
        raise ValueError("Empty analysis-v2 BB set")
    return {
        "target": target_inst,
        "svf_backend": "SVF-2.9/SVFG",
        "svf_semantics": "BACKWARD_VALUE_FLOW_ONLY",
        "v2_semantics": "PARTIAL_SSA_WITH_CONTROL",
        "validated_for_supervision": False,
        "jaccard": len(a & b) / len(a | b),
        "svf_only_bbs": sorted(a - b),
        "v2_only_bbs": sorted(b - a),
        "shared_bbs": len(a & b),
        "svf_bbs": len(a),
        "v2_bbs": len(b),
        "v2_unknown_boundaries": old.unknown_boundaries,
        "v2_truncated": old.truncated,
        "warning": (
            "SVF value-flow excludes control dependence while v2 includes "
            "partial SSA/control relations. No completeness or accuracy "
            "conclusion follows from a Jaccard difference."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-dir", type=Path, required=True)
    parser.add_argument("--svf-report", type=Path)
    parser.add_argument("--target-inst", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = compare(
        args.case_dir,
        args.svf_report or (args.case_dir / "svf_backend/svf_slice.json"),
        args.target_inst,
    )
    content = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
    else:
        print(content, end="")


if __name__ == "__main__":
    main()

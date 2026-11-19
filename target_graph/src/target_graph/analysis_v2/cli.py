"""Explore instruction-level dependencies without exporting training labels.

Example:
  python -m target_graph.analysis_v2.cli \
    --case-dir cases/libming-4.7.1_swftophp_CVE-2017-7578 \
    --target-bb <legacy_bb_id> --list-targets
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .graph import DependencyGraph
from .slicing import backward_slice


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-dir", required=True, type=Path)
    parser.add_argument("--target-inst")
    parser.add_argument("--target-bb")
    parser.add_argument("--line", type=int)
    parser.add_argument("--opcode")
    parser.add_argument("--list-targets", action="store_true")
    parser.add_argument("--max-call-depth", type=int, default=8)
    parser.add_argument("--max-states", type=int, default=200_000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    graph = DependencyGraph.from_directory(args.case_dir)
    if args.list_targets:
        if not args.target_bb:
            parser.error("--list-targets requires --target-bb")
        candidates = graph.candidate_fault_instructions(
            args.target_bb, args.line, args.opcode
        )
        print(json.dumps(
            [vars(candidate) for candidate in candidates], indent=2
        ))
        return

    target = args.target_inst
    if not target:
        if not args.target_bb:
            parser.error("Specify --target-inst or --target-bb with optional --line/--opcode")
        candidates = graph.candidate_fault_instructions(
            args.target_bb, args.line, args.opcode
        )
        if len(candidates) != 1:
            parser.error(
                f"Ambiguous target criterion ({len(candidates)} matching instructions). "
                "Use --list-targets and then --target-inst; no first-BB fallback."
            )
        target = candidates[0].id
    node = graph.nodes.get(target)
    if node is None or node.kind != "instruction":
        parser.error(f"Target must be an instruction node, got: {target!r}")

    result = backward_slice(
        graph, target,
        max_call_depth=args.max_call_depth,
        max_states=args.max_states,
    )
    payload = result.as_dict()
    payload["provenance_status"] = "EXPLORATORY_ONLY"
    payload["fault_operand_coverage"] = None
    payload["source_case"] = str(args.case_dir)
    payload["graph_nodes"] = len(graph.nodes)
    payload["graph_edges"] = graph.edge_count

    rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"[analysis-v2] wrote {args.output}")
    else:
        print(rendered)


if __name__ == "__main__":
    main()

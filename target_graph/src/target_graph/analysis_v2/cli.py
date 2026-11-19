"""Explore instruction-level dependencies without exporting training labels.

Example:
  python -m target_graph.analysis_v2.cli \
    --case-dir cases/libming-4.7.1_swftophp_CVE-2017-7578 \
    --target-bb <legacy_bb_id> --list-targets
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .graph import DependencyGraph
from .slicing import backward_slice


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-dir", required=True, type=Path)
    parser.add_argument("--target-inst")
    parser.add_argument("--target-bb")
    parser.add_argument("--source-file", help="Source basename or exact debug path; list all inlined LLVM owners")
    parser.add_argument("--line", type=int)
    parser.add_argument("--opcode")
    parser.add_argument("--list-targets", action="store_true")
    parser.add_argument("--max-call-depth", type=int, default=8)
    parser.add_argument("--max-states", type=int, default=200_000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    graph = DependencyGraph.from_directory(args.case_dir)

    def find_candidates():
        if args.source_file:
            if args.line is None:
                parser.error("--source-file requires --line")
            matches = graph.candidate_fault_instructions_by_source(
                args.source_file, args.line, args.opcode
            )
            if args.target_bb:
                matches = [n for n in matches if n.bb_id == args.target_bb]
            return matches
        if args.target_bb:
            return graph.candidate_fault_instructions(
                args.target_bb, args.line, args.opcode
            )
        parser.error("Specify --target-inst, --target-bb or --source-file with --line")

    if args.list_targets:
        candidates = find_candidates()
        print(json.dumps(
            [vars(candidate) for candidate in candidates], indent=2
        ))
        if args.source_file and len(candidates) > 1:
            print(
                f"[analysis-v2] {len(candidates)} IR instructions share the source "
                "criterion. These may be inlined copies. Source location alone "
                "does NOT prove the PoC executed any particular candidate.",
                file=sys.stderr,
            )
        return

    target = args.target_inst
    if not target:
        candidates = find_candidates()
        if len(candidates) != 1:
            parser.error(
                f"Ambiguous target criterion ({len(candidates)} matching instructions). "
                "Use --list-targets and verify the actual executed instruction "
                "against the PoC trace before passing --target-inst."
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

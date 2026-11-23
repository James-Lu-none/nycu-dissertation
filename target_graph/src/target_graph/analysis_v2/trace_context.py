"""Inspect last PoC trace PCs and inline frames without guessing fault BB identity.

This tool is an *evidence shortlist*, NOT PC-to-LLVM-instruction proof.
ASan-instrumented binaries and static bitcode may have different IR layouts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, List, Sequence, Tuple

from target_graph.tracing.symbolizer import parse_trace_pcs, symbolize_pcs

from .graph import DependencyGraph, DependencyNode

Frame = Tuple[str, str, int]


def identify_candidate_owners(
    graph: DependencyGraph,
    frames: Sequence[Frame],
    source_file: str,
    line: int,
    opcode: str | None = None,
) -> List[DependencyNode]:
    """Return candidate LLVM owners when a symbolized inline stack matches.

    llvm-symbolizer returns (innermost inline frame, ..., outermost frame).
    The outermost *machine-code owner* is a stronger function match than
    the inner source function; both are still insufficient to identify a
    particular LLVM instruction when duplicated or differently optimized.
    """
    if not frames:
        return []
    requested_name = Path(source_file).name
    at_source = any(
        Path(filename).name == requested_name and frame_line == line
        for _, filename, frame_line in frames
    )
    if not at_source:
        return []
    outer_owner = frames[-1][0]
    # Some symbolizers append C argument signatures. Do not use substring
    # matching: it would silently merge different functions.
    outer_owner = outer_owner.split("(", 1)[0].strip()
    return [
        node for node in graph.candidate_fault_instructions_by_source(
            source_file, line, opcode
        )
        if node.function == outer_owner
    ]


def build_trace_context(
    graph: DependencyGraph,
    pcs: Sequence[int],
    pc_frames: dict[int, List[Frame]],
    source_file: str,
    line: int,
    opcode: str | None,
) -> dict[str, Any]:
    candidates = graph.candidate_fault_instructions_by_source(
        source_file, line, opcode
    )
    events = []
    matched_ids: set[str] = set()
    for pc in pcs:
        frames = pc_frames.get(pc, [])
        matches = identify_candidate_owners(
            graph, frames, source_file, line, opcode
        )
        matched_ids.update(n.id for n in matches)
        events.append({
            "pc": f"0x{pc:x}",
            "inline_frames_innermost_first": [
                {"function": fn, "source_file": path, "line": lineno}
                for fn, path, lineno in frames
            ],
            "source_location_in_inline_stack": any(
                Path(path).name == Path(source_file).name and lineno == line
                for _, path, lineno in frames
            ),
            "potential_ir_instruction_ids": [n.id for n in matches],
        })
    return {
        "schema_version": 1,
        "analysis_status": "TRACE_CONTEXT_DIAGNOSTIC_ONLY",
        "fault_instruction_confirmed": False,
        "reason": (
            "PC frame symbolization is not a bijective mapping to LLVM "
            "instructions: ASan instrumentation, optimization, duplicate "
            "source lines and inlining may change instruction identities."
        ),
        "source_criterion": {
            "file": source_file, "line": line, "opcode": opcode
        },
        "all_source_candidates": [
            {
                "id": n.id, "function": n.function, "bb_id": n.bb_id,
                "source_file": n.source_file, "line": n.line,
            }
            for n in candidates
        ],
        "trace_frame_candidate_ids": sorted(matched_ids),
        "recent_events": events,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-dir", type=Path, required=True)
    parser.add_argument("--trace-file", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--source-file", required=True)
    parser.add_argument("--line", type=int, required=True)
    parser.add_argument("--opcode", default="store")
    parser.add_argument("--last-events", type=int, default=128)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.line <= 0 or args.last_events < 1 or args.last_events > 4096:
        parser.error("--line must be positive and --last-events must be in 1..4096")
    case_dir = args.case_dir
    trace_file = args.trace_file or (case_dir / "trace_crash.txt")
    binary = args.binary
    if binary is None:
        binaries = list(case_dir.glob("*_inst"))
        if len(binaries) != 1:
            parser.error("Provide --binary: expected exactly one *_inst binary")
        binary = binaries[0]
    if not trace_file.is_file() or not binary.is_file():
        parser.error(f"Trace and instrumented binary must exist: {trace_file}, {binary}")

    pcs = parse_trace_pcs(trace_file)
    if not pcs:
        parser.error("No valid trace PCs found")
    sample = pcs[-args.last_events:]
    unique = list(dict.fromkeys(sample))
    graph = DependencyGraph.from_directory(case_dir)
    # Bound the symbolization batch for command-line size and cost.
    pc_frames = {}
    for start in range(0, len(unique), 128):
        pc_frames.update(symbolize_pcs(unique[start:start + 128], binary))
    result = build_trace_context(
        graph, sample, pc_frames, args.source_file, args.line, args.opcode
    )
    result["trace_file"] = str(trace_file)
    result["instrumented_binary"] = str(binary)
    result["total_trace_events"] = len(pcs)
    result["sampled_recent_events"] = len(sample)
    result["symbolized_events"] = sum(bool(pc_frames.get(pc)) for pc in sample)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"Trace context: {len(result['all_source_candidates'])} source candidates; "
        f"{len(result['trace_frame_candidate_ids'])} suggested by recent inline frames. "
        f"Exported {args.output} (NOT a verified LLVM instruction identity)."
    )


if __name__ == "__main__":
    main()

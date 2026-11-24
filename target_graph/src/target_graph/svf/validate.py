"""Fail-closed identity and evidence validation for the SVF-2.9 backend.

The result is ALWAYS exploratory: a native SVFG value-flow traversal is not
the same as a verified vulnerability root-cause slice or a complete PDG.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from target_graph.dg.validate import _legacy_bbs, _records, _v2_instructions

SVF_COMMIT = "0e56bc038bf207a1ca320b5f5ad241e13ab33e14"
EDGE_KINDS = frozenset({
    "CALL_DIRECT_VALUE_FLOW",
    "RETURN_DIRECT_VALUE_FLOW",
    "CALL_INDIRECT_VALUE_FLOW",
    "RETURN_INDIRECT_VALUE_FLOW",
    "THREAD_INDIRECT_VALUE_FLOW",
    "INTRA_INDIRECT_VALUE_FLOW",
    "INTRA_DIRECT_VALUE_FLOW",
})


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def preflight(
    before: Path,
    target: str,
    *,
    bb_map: Path | None = None,
    v2_nodes: Path | None = None,
) -> dict[str, dict]:
    original = _records(before)
    if not original:
        raise ValueError("Original bitcode has no tagged LLVM instructions")
    if target not in original:
        raise ValueError(
            "Selected target instruction was not tagged in the original bitcode; "
            "stop before SVF analysis and repair build/target mapping"
        )
    if bb_map is not None:
        if not bb_map.is_file():
            raise ValueError(f"Missing BB mapping: {bb_map}")
        bbs = _legacy_bbs(bb_map)
        missing = {row["bb_id"] for row in original.values()} - bbs
        if missing:
            raise ValueError(f"Original identities not present in bb_map: {len(missing)}")
    if v2_nodes is not None:
        if not v2_nodes.is_file():
            raise ValueError(f"Missing v2 nodes: {v2_nodes}")
        if set(original) != _v2_instructions(v2_nodes):
            raise ValueError("Original identities differ from analysis_v2_nodes.jsonl")
    return original


def validate_svf(
    before: Path,
    raw_path: Path,
    target: str,
    source_bc: Path,
    *,
    bb_map: Path | None = None,
    v2_nodes: Path | None = None,
) -> dict[str, Any]:
    original = preflight(before, target, bb_map=bb_map, v2_nodes=v2_nodes)
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("backend") != "SVF-2.9/SVFG":
        raise ValueError("Unexpected SVF backend / invalid raw output")
    if raw.get("target") != target:
        raise ValueError("SVF target instruction mismatch")
    if raw.get("analysis") != "BACKWARD_VALUE_FLOW_ONLY":
        raise ValueError("Unexpected SVF analysis semantics")
    if any(raw.get(k) is not False for k in (
        "validated_for_supervision", "target_site_verified",
        "context_sensitive", "control_dependencies_included"
    )):
        raise ValueError("SVF output overclaims verification, context or control dependencies")

    nodes, edges = raw.get("svfg_nodes"), raw.get("svfg_edges")
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("SVFG did not return visited nodes")
    if not isinstance(edges, list):
        raise ValueError("SVFG edges must be a list")
    by_svfg_id: dict[int, dict] = {}
    mapped_instruction_ids: set[str] = set()
    for node in nodes:
        if not isinstance(node, dict):
            raise ValueError("Invalid SVFG node record")
        node_id = node.get("svfg_id")
        if type(node_id) is not int or node_id < 0 or node_id in by_svfg_id:
            raise ValueError("Invalid or duplicated SVFG node ID")
        by_svfg_id[node_id] = node
        inst = node.get("instruction_id")
        bb = node.get("bb_id")
        if inst is not None:
            if not isinstance(inst, str) or inst not in original:
                raise ValueError(f"Unrecognized LLVM instruction identity: {inst!r}")
            if bb != original[inst]["bb_id"]:
                raise ValueError("SVFG instruction mapped to a different original BB")
            mapped_instruction_ids.add(inst)
        elif bb is not None:
            raise ValueError("Unmapped SVFG node has an asserted BB identity")

    if target not in mapped_instruction_ids:
        raise ValueError("Selected target is absent from SVF value-flow evidence")
    seeds = raw.get("target_seed_svfg_ids")
    if not isinstance(seeds, list) or not seeds or any(
        type(i) is not int or i not in by_svfg_id or
        by_svfg_id[i].get("instruction_id") != target for i in seeds
    ):
        raise ValueError("Target seeds do not map to requested original instruction")
    for edge in edges:
        if not isinstance(edge, dict):
            raise ValueError("Invalid SVFG edge record")
        if (edge.get("src_svfg_id") not in by_svfg_id or
                edge.get("dst_svfg_id") not in by_svfg_id):
            raise ValueError("Dangling SVFG value-flow edge")
        if edge.get("kind") not in EDGE_KINDS or edge.get("analysis_status") != "may":
            raise ValueError("Unknown edge semantics or overconfident evidence")

    bbs = {original[inst]["bb_id"] for inst in mapped_instruction_ids}
    if set(raw.get("instruction_ids", [])) != mapped_instruction_ids:
        raise ValueError("Mismatch between SVFG nodes and instruction list")
    if set(raw.get("basic_blocks", [])) != bbs:
        raise ValueError("Mismatch between mapped SVFG instructions and BB list")
    if raw.get("visited_svfg_nodes") != len(nodes) or raw.get("traversed_edges") != len(edges):
        raise ValueError("SVFG traversal counts are inconsistent")
    if raw.get("mapped_svfg_nodes") != sum(
        node.get("instruction_id") is not None for node in nodes
    ):
        raise ValueError("SVFG mapped-node count mismatch")
    if raw.get("unmapped_svfg_nodes") != sum(
        node.get("instruction_id") is None for node in nodes
    ):
        raise ValueError("SVFG unmapped-node count mismatch")

    return {
        "schema_version": 1,
        "backend": "SVF-2.9/SVFG",
        "svf_commit": SVF_COMMIT,
        "analysis": "BACKWARD_VALUE_FLOW_ONLY",
        "status": "EXPLORATORY_ONLY",
        "validated_for_supervision": False,
        "target_site_verified": False,
        "context_sensitive": False,
        "control_dependencies_included": False,
        "target": target,
        "original_bitcode_sha256": sha256_file(source_bc),
        "original_instruction_count": len(original),
        "original_basic_block_count": len({r["bb_id"] for r in original.values()}),
        "svfg_total_nodes": raw.get("svfg_total_nodes"),
        "visited_svfg_nodes": len(nodes),
        "traversed_edges": len(edges),
        "target_seed_svfg_ids": seeds,
        "mapped_svfg_nodes": raw["mapped_svfg_nodes"],
        "unmapped_svfg_nodes": raw["unmapped_svfg_nodes"],
        "instruction_ids": sorted(mapped_instruction_ids),
        "basic_blocks": sorted(bbs),
        "unmapped_note": (
            "SVFG phi/memory/call nodes without a unique LLVM instruction "
            "remain in raw SVFG and are not invented as BB-level labels"
        ),
        "analysis_limitations": [
            "SVFG value-flow only: control dependencies are not included",
            "Context-insensitive reverse traversal can mix call contexts",
            "Fault-site/PoC provenance requires separate runtime verification",
            "SVFG membership is not a ground-truth vulnerability label",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["preflight", "finish"])
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--target-inst", required=True)
    parser.add_argument("--raw", type=Path)
    parser.add_argument("--source-bc", type=Path)
    parser.add_argument("--bb-map", type=Path)
    parser.add_argument("--v2-nodes", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    kwargs = {"bb_map": args.bb_map, "v2_nodes": args.v2_nodes}
    if args.mode == "preflight":
        original = preflight(args.before, args.target_inst, **kwargs)
        print(f"[svf] preflight OK: {len(original)} tagged original instructions")
        return
    if not args.raw or not args.source_bc or not args.output:
        parser.error("finish requires --raw, --source-bc and --output")
    result = validate_svf(
        args.before, args.raw, args.target_inst, args.source_bc, **kwargs
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.output.with_name(args.output.name + ".tmp")
    tmp.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, args.output)
    print(
        f"[svf] {len(result['basic_blocks'])} original BBs in value-flow "
        "candidate set (EXPLORATORY_ONLY, not training labels)"
    )


if __name__ == "__main__":
    main()

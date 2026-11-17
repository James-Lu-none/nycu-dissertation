"""Export raw extracted JSONL entries to canonical Parquet tables and metadata."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from target_graph.graphs.relations import dump_relation_vocab
from target_graph.graphs.schema import (
    EDGES_ARROW_SCHEMA,
    FUNCTIONS_ARROW_SCHEMA,
    NODES_ARROW_SCHEMA,
    GraphMetadata,
)
from target_graph.graphs.validate import validate_graph_bundle


def export_raw_to_parquet(
    raw_dir: Path,
    output_dir: Path,
    build_id: str,
    ir_hash: str = "unknown",
    llvm_version: str = "14.0",
) -> Dict[str, Any]:
    """Convert raw_nodes.jsonl and raw_edges.jsonl into canonical Parquet tables."""
    output_dir.mkdir(parents=True, exist_ok=True)

    raw_nodes_file = raw_dir / "raw_nodes.jsonl"
    raw_edges_file = raw_dir / "raw_edges.jsonl"

    if not raw_nodes_file.exists():
        raise FileNotFoundError(f"Missing {raw_nodes_file}")
    if not raw_edges_file.exists():
        raise FileNotFoundError(f"Missing {raw_edges_file}")

    # 1. Parse and deduplicate nodes
    nodes: Dict[str, Dict[str, Any]] = {}
    functions: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "function_id": "",
        "entry_bb": "",
        "exit_bbs": set(),
        "callsites": set(),
        "source_hash": "",
    })

    with open(raw_nodes_file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            bb_id = rec["bb_id"]
            if bb_id not in nodes:
                nodes[bb_id] = {
                    "build_id": rec.get("build_id", build_id),
                    "bb_id": bb_id,
                    "function_id": rec["function_id"],
                    "source_spans": json.dumps(rec.get("source_spans", [])),
                    "instruction_ids": json.dumps(rec.get("instruction_ids", [])),
                    "mapping_status": rec.get("mapping_status", "mapped"),
                    "is_entry": rec.get("is_entry", False),
                    "is_exit": rec.get("is_exit", False),
                }

                func_id = rec["function_id"]
                functions[func_id]["function_id"] = func_id
                if rec.get("is_entry", False):
                    functions[func_id]["entry_bb"] = bb_id
                if rec.get("is_exit", False):
                    functions[func_id]["exit_bbs"].add(bb_id)

    nodes_df = pd.DataFrame(list(nodes.values()))
    nodes_table = pa.Table.from_pandas(nodes_df, schema=NODES_ARROW_SCHEMA, preserve_index=False)
    pq.write_table(nodes_table, output_dir / "nodes.parquet")

    # 2. Parse and aggregate edges: (src, dst, relation_id, callsite_id)
    edge_map: Dict[Tuple[str, str, int, str], Dict[str, Any]] = {}
    valid_bb_ids = set(nodes.keys())

    with open(raw_edges_file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            src = rec["src_bb"]
            dst = rec["dst_bb"]
            # Exclude dangling edges or invalid endpoints
            if src not in valid_bb_ids or dst not in valid_bb_ids:
                continue

            rel_id = int(rec["relation_id"])
            callsite_id = rec.get("callsite_id", "")
            key = (src, dst, rel_id, callsite_id)

            if key not in edge_map:
                edge_map[key] = {
                    "src_bb": src,
                    "dst_bb": dst,
                    "relation_id": rel_id,
                    "callsite_id": callsite_id,
                    "evidence_count": 0,
                    "analysis_status": rec.get("analysis_status", "verified"),
                    "evidence_ref": f"{src}->{dst}:{rel_id}",
                }
            edge_map[key]["evidence_count"] += rec.get("evidence_count", 1)

            if callsite_id and src in nodes:
                func_id = nodes[src]["function_id"]
                functions[func_id]["callsites"].add(callsite_id)

    edges_df = pd.DataFrame(list(edge_map.values()))
    edges_table = pa.Table.from_pandas(edges_df, schema=EDGES_ARROW_SCHEMA, preserve_index=False)
    pq.write_table(edges_table, output_dir / "edges.parquet")

    # 3. Export functions table
    func_rows = []
    for fid, fdata in functions.items():
        func_rows.append({
            "function_id": fid,
            "entry_bb": fdata["entry_bb"],
            "exit_bbs": json.dumps(sorted(fdata["exit_bbs"])),
            "callsites": json.dumps(sorted(fdata["callsites"])),
            "source_hash": fdata["source_hash"],
        })
    funcs_df = pd.DataFrame(func_rows)
    funcs_table = pa.Table.from_pandas(funcs_df, schema=FUNCTIONS_ARROW_SCHEMA, preserve_index=False)
    pq.write_table(funcs_table, output_dir / "functions.parquet")

    # 4. Export relation_to_id.json
    dump_relation_vocab(output_dir / "relation_to_id.json", include_reverse=False)

    # 5. Export graph_metadata.json
    unresolved_calls = 0
    pass_summary_file = raw_dir / "pass_summary.json"
    if pass_summary_file.exists():
        try:
            with open(pass_summary_file, "r", encoding="utf-8") as f:
                psum = json.load(f)
                unresolved_calls = int(psum.get("unresolved_calls", 0))
        except Exception:
            pass

    if ir_hash == "unknown":
        bc_files = list(raw_dir.glob("*.bc"))
        if bc_files:
            import hashlib
            ir_hash = hashlib.sha256(bc_files[0].read_bytes()).hexdigest()

    meta = GraphMetadata(
        build_id=build_id,
        ir_hash=ir_hash,
        llvm_version=llvm_version,
        unresolved_calls=unresolved_calls,
        node_count=len(nodes_df),
        edge_count=len(edges_df),
    )
    with open(output_dir / "graph_metadata.json", "w", encoding="utf-8") as f:
        f.write(meta.model_dump_json(indent=2))

    # Validate output bundle
    stats = validate_graph_bundle(output_dir)
    return stats


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Export raw JSONL files to canonical Parquet bundle.")
    parser.add_argument("--raw-dir", type=Path, required=True, help="Directory containing raw JSONL files")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory to save Parquet files")
    parser.add_argument("--build-id", type=str, required=True, help="Build identifier")
    parser.add_argument("--ir-hash", type=str, default="unknown", help="Bitcode IR hash")
    parser.add_argument("--llvm-version", type=str, default="14.0", help="LLVM version")
    args = parser.parse_args()

    stats = export_raw_to_parquet(
        raw_dir=args.raw_dir,
        output_dir=args.output_dir,
        build_id=args.build_id,
        ir_hash=args.ir_hash,
        llvm_version=args.llvm_version,
    )
    print(f"[SUCCESS] Exported and validated Parquet bundle: {stats['num_nodes']} nodes, {stats['num_edges']} edges in {args.output_dir}")


if __name__ == "__main__":
    main()



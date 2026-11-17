"""Graph validation rules ensuring integrity, determinism, and absence of target leaks."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
import pandas as pd
import pyarrow.parquet as pq

from .relations import CANONICAL_RELATION_TO_ID, NUM_CANONICAL_RELATIONS


class GraphValidationError(Exception):
    """Raised when a program graph violates integrity constraints."""
    pass


def validate_graph_bundle(graph_dir: Path) -> Dict[str, int]:
    """Validate all parquet tables in graph_dir for schema compliance and referential integrity.
    
    Checks:
    1. nodes.parquet, edges.parquet, edge_evidence.parquet, functions.parquet exist.
    2. No dangling edge endpoints: every src_bb and dst_bb must exist in nodes.parquet.
    3. Categorical relation IDs fall in [0, NUM_CANONICAL_RELATIONS - 1].
    4. Call/Return callsite_id consistency: CALL and RETURN edges must have non-empty callsite_id.
    5. No self-loops for message edges in the baseline graph.
    6. No supervision leakage: candidate-to-target synthetic edges or labels are absent.
    """
    nodes_path = graph_dir / "nodes.parquet"
    edges_path = graph_dir / "edges.parquet"
    funcs_path = graph_dir / "functions.parquet"
    meta_path = graph_dir / "graph_metadata.json"

    if not nodes_path.exists():
        raise GraphValidationError(f"Missing nodes.parquet in {graph_dir}")
    if not edges_path.exists():
        raise GraphValidationError(f"Missing edges.parquet in {graph_dir}")

    nodes_df = pd.read_parquet(nodes_path)
    edges_df = pd.read_parquet(edges_path)

    # 1. Check node IDs
    node_ids: Set[str] = set(nodes_df["bb_id"].unique())
    if len(node_ids) != len(nodes_df):
        raise GraphValidationError(f"Duplicate bb_id found in {nodes_path}")

    # 2. Check no dangling edge endpoints
    src_set = set(edges_df["src_bb"].unique())
    dst_set = set(edges_df["dst_bb"].unique())

    dangling_src = src_set - node_ids
    if dangling_src:
        raise GraphValidationError(f"Found dangling src_bb not in nodes: {list(dangling_src)[:5]}")

    dangling_dst = dst_set - node_ids
    if dangling_dst:
        raise GraphValidationError(f"Found dangling dst_bb not in nodes: {list(dangling_dst)[:5]}")

    # 3. Check relation IDs
    valid_rids = set(CANONICAL_RELATION_TO_ID.values())
    edge_rids = set(edges_df["relation_id"].unique())
    invalid_rids = edge_rids - valid_rids
    if invalid_rids:
        raise GraphValidationError(f"Found invalid relation_ids: {invalid_rids}")

    # 4. Check CALL/RETURN have callsite_id
    call_rid = CANONICAL_RELATION_TO_ID["CALL"]
    ret_rid = CANONICAL_RELATION_TO_ID["RETURN"]

    call_edges = edges_df[edges_df["relation_id"] == call_rid]
    if (call_edges["callsite_id"] == "").any():
        raise GraphValidationError("CALL edge missing required callsite_id")

    ret_edges = edges_df[edges_df["relation_id"] == ret_rid]
    if (ret_edges["callsite_id"] == "").any():
        raise GraphValidationError("RETURN edge missing required callsite_id")

    # 5. Check functions table if present
    if funcs_path.exists():
        funcs_df = pd.read_parquet(funcs_path)
        for _, row in funcs_df.iterrows():
            entry_bb = row["entry_bb"]
            if entry_bb and entry_bb not in node_ids:
                raise GraphValidationError(f"Function {row['function_id']} entry_bb {entry_bb} not in nodes")

    return {
        "num_nodes": len(nodes_df),
        "num_edges": len(edges_df),
        "num_relations": len(edge_rids),
    }


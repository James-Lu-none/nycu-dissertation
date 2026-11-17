"""Interprocedural execution graph distance and reachability analysis."""
from __future__ import annotations

from collections import deque
from typing import Dict, List, Optional, Set, Tuple
import pandas as pd
import torch

from target_graph.graphs.relations import CANONICAL_RELATION_TO_ID
from target_graph.models.rgcn import DistanceBucketEmbedding


# Permitted relations in the execution graph G_exec (forward CFG + CALL + RETURN)
EXEC_RELATIONS: Set[int] = {
    CANONICAL_RELATION_TO_ID["CFG_T"],
    CANONICAL_RELATION_TO_ID["CFG_F"],
    CANONICAL_RELATION_TO_ID["CFG_NEXT"],
    CANONICAL_RELATION_TO_ID["CFG_OTHER"],
    CANONICAL_RELATION_TO_ID["CALL"],
    CANONICAL_RELATION_TO_ID["RETURN"],
}


def build_reverse_exec_adjacency(
    edges_df: pd.DataFrame,
    valid_bbs: Optional[Set[str]] = None,
) -> Dict[str, List[str]]:
    """Build reverse adjacency list for G_exec: dst -> [src] for backward search from target.
    
    Only includes forward CFG, CALL, and RETURN relations. DDG and CDG are strictly excluded.
    """
    exec_mask = edges_df["relation_id"].isin(EXEC_RELATIONS)
    exec_edges = edges_df[exec_mask]

    rev_adj: Dict[str, List[str]] = {}
    if valid_bbs is not None:
        for bb in valid_bbs:
            rev_adj[bb] = []

    for src_raw, dst_raw in zip(exec_edges["src_bb"], exec_edges["dst_bb"]):
        src = str(src_raw)
        dst = str(dst_raw)
        if valid_bbs is not None and (src not in valid_bbs or dst not in valid_bbs):
            continue
        rev_adj.setdefault(dst, []).append(src)
        if src not in rev_adj:
            rev_adj[src] = []

    return rev_adj


def compute_execution_distances_to_target(
    target_bb: str,
    all_bbs: Set[str],
    edges_df: pd.DataFrame,
) -> Tuple[Dict[str, float], Dict[str, str]]:
    """Compute shortest-path execution distance d_exec(i, t) from all nodes i to target t.
    
    Returns:
        (distances, statuses):
            distances: bb_id -> float distance
            statuses: bb_id -> 'finite', 'unreachable_proven', or 'analysis_unknown'
    """
    if target_bb not in all_bbs:
        # Target not in analyzed basic blocks
        return {bb: float("inf") for bb in all_bbs}, {bb: "analysis_unknown" for bb in all_bbs}

    rev_adj = build_reverse_exec_adjacency(edges_df, valid_bbs=all_bbs)

    distances: Dict[str, float] = {bb: float("inf") for bb in all_bbs}
    statuses: Dict[str, str] = {bb: "unreachable_proven" for bb in all_bbs}

    # BFS from target in transposed G_exec
    queue = deque([target_bb])
    distances[target_bb] = 0.0
    statuses[target_bb] = "finite"
    visited: Set[str] = {target_bb}

    while queue:
        curr = queue.popleft()
        curr_dist = distances[curr]

        for pred in rev_adj.get(curr, []):
            if pred not in visited:
                visited.add(pred)
                distances[pred] = curr_dist + 1.0
                statuses[pred] = "finite"
                queue.append(pred)

    return distances, statuses


def get_execution_distance_buckets(
    target_bb: str,
    all_bbs_ordered: List[str],
    edges_df: pd.DataFrame,
) -> torch.Tensor:
    """Compute tensor of integer distance bucket IDs for ordered basic blocks.
    
    Returns:
        torch.Tensor of shape [num_nodes], dtype torch.long.
    """
    all_bbs_set = set(all_bbs_ordered)
    distances, statuses = compute_execution_distances_to_target(target_bb, all_bbs_set, edges_df)

    bucket_ids = [
        DistanceBucketEmbedding.bucketize(distances[bb], statuses[bb])
        for bb in all_bbs_ordered
    ]

    return torch.tensor(bucket_ids, dtype=torch.long)

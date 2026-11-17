"""Unit tests for interprocedural execution graph distance computation."""
from __future__ import annotations

import pandas as pd
import pytest
import torch

from target_graph.analysis.exec_distance import (
    compute_execution_distances_to_target,
    get_execution_distance_buckets,
)
from target_graph.graphs.relations import CANONICAL_RELATION_TO_ID
from target_graph.models.rgcn import DistanceBucketEmbedding


def test_execution_distance_bfs():
    # Construct a small graph:
    # bb1 -> bb2 (CFG_T) -> bb3 (CFG_NEXT) -> target_bb (CALL)
    # bb_unreachable (no path to target)
    edges = [
        {"src_bb": "bb1", "dst_bb": "bb2", "relation_id": CANONICAL_RELATION_TO_ID["CFG_T"]},
        {"src_bb": "bb2", "dst_bb": "bb3", "relation_id": CANONICAL_RELATION_TO_ID["CFG_NEXT"]},
        {"src_bb": "bb3", "dst_bb": "target_bb", "relation_id": CANONICAL_RELATION_TO_ID["CALL"]},
        # DDG edge from bb_unreachable -> target_bb (must be ignored by G_exec!)
        {"src_bb": "bb_unreachable", "dst_bb": "target_bb", "relation_id": CANONICAL_RELATION_TO_ID["DDG_SSA"]},
    ]
    edges_df = pd.DataFrame(edges)
    all_bbs = {"bb1", "bb2", "bb3", "target_bb", "bb_unreachable"}

    distances, statuses = compute_execution_distances_to_target("target_bb", all_bbs, edges_df)

    assert distances["target_bb"] == 0.0
    assert statuses["target_bb"] == "finite"

    assert distances["bb3"] == 1.0
    assert statuses["bb3"] == "finite"

    assert distances["bb2"] == 2.0
    assert statuses["bb2"] == "finite"

    assert distances["bb1"] == 3.0
    assert statuses["bb1"] == "finite"

    # bb_unreachable only had a DDG edge, which is excluded from G_exec!
    assert distances["bb_unreachable"] == float("inf")
    assert statuses["bb_unreachable"] == "unreachable_proven"


def test_distance_bucket_embedding_mapping():
    ordered_bbs = ["target", "dist_1", "dist_2", "dist_3", "unreachable"]
    edges = [
        {"src_bb": "dist_1", "dst_bb": "target", "relation_id": CANONICAL_RELATION_TO_ID["CFG_NEXT"]},
        {"src_bb": "dist_2", "dst_bb": "dist_1", "relation_id": CANONICAL_RELATION_TO_ID["CFG_NEXT"]},
        {"src_bb": "dist_3", "dst_bb": "dist_2", "relation_id": CANONICAL_RELATION_TO_ID["CFG_NEXT"]},
    ]
    edges_df = pd.DataFrame(edges)

    buckets = get_execution_distance_buckets("target", ordered_bbs, edges_df)
    assert buckets.shape == (5,)
    assert buckets[0].item() == 0   # target itself
    assert buckets[1].item() == 1   # dist 1
    assert buckets[2].item() == 2   # dist 2
    assert buckets[3].item() == 3   # dist 3 (bucket 3 is dist 3-4)
    assert buckets[4].item() == 9   # unreachable_proven (bucket 9)

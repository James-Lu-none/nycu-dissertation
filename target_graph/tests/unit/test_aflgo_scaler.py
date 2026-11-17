"""Unit tests for Phase II: AFLGo distance scaling adapter."""
from __future__ import annotations

import math
from pathlib import Path
import pytest
import torch

from target_graph.analysis.aflgo_scaler import AFLGoDistanceScaler
from target_graph.training.datasets import TargetGraphSample
from target_graph.training.trainer import TargetConditionedModel, TrainerConfig


def test_g_eta_properties():
    config = TrainerConfig(in_dim=16, hidden_dim=8, num_layers=1, dist_embed_dim=4, mlp_hidden_dim=8, device="cpu")
    model = TargetConditionedModel(config)
    scaler = AFLGoDistanceScaler(model, eta=1.5)

    # 1. Monotonicity: higher score -> smaller g_eta
    scores = torch.tensor([-10.0, 0.0, 5.0, 20.0])
    g_vals = scaler.g_eta(scores).numpy()

    assert g_vals[0] > g_vals[1] > g_vals[2] > g_vals[3]

    # 2. Boundedness: in [exp(-1.5), 1.0]
    lower_bound = math.exp(-1.5)
    for v in g_vals:
        assert lower_bound <= v <= 1.0

    # 3. Exact identity when eta == 0
    scaler_zero = AFLGoDistanceScaler(model, eta=0.0)
    g_zero = scaler_zero.g_eta(scores).numpy()
    for v in g_zero:
        assert math.isclose(v, 1.0, rel_tol=1e-5)


def test_distance_file_scaling(tmp_path: Path):
    num_nodes = 3
    x = torch.randn(num_nodes, 16)
    edge_index = torch.tensor([[0, 1], [1, 2]], dtype=torch.long)
    edge_type = torch.zeros(2, dtype=torch.long)
    dist_buckets = torch.tensor([0, 1, 2], dtype=torch.long)

    pos_mask = torch.tensor([True, False, False])
    unlabeled_mask = torch.tensor([False, True, False])
    neg_mask = torch.tensor([False, False, False])

    sample = TargetGraphSample(
        case_id="scaler_test",
        target_bb="bb_0",
        x=x,
        edge_index=edge_index,
        edge_type=edge_type,
        dist_buckets=dist_buckets,
        target_idx=0,
        pos_mask=pos_mask,
        unlabeled_mask=unlabeled_mask,
        neg_mask=neg_mask,
        bb_to_idx={"bb_0": 0, "bb_1": 1, "bb_2": 2},
        idx_to_bb=["bb_0", "bb_1", "bb_2"],
    )

    config = TrainerConfig(in_dim=16, hidden_dim=8, num_layers=1, dist_embed_dim=4, mlp_hidden_dim=8, device="cpu")
    model = TargetConditionedModel(config)
    scaler = AFLGoDistanceScaler(model, eta=1.0)

    # Create dummy AFLGo distance.cfg.txt
    dist_in = tmp_path / "distance.cfg.txt"
    dist_in.write_text(
        "bb_0,10.0\n"
        "bb_1,20.0\n"
        "bb_unmapped,50.0\n"
    )

    dist_out = tmp_path / "distance.scaled.cfg.txt"
    metrics = scaler.scale_distance_file(dist_in, dist_out, sample)

    assert metrics.total_entries == 3
    assert metrics.mapped_entries == 2
    assert metrics.unmapped_entries == 1

    # Read output lines
    out_lines = dist_out.read_text().splitlines()
    assert len(out_lines) == 3

    # Check unmapped preserves exact original distance
    unmapped_line = [l for l in out_lines if "bb_unmapped" in l][0]
    assert float(unmapped_line.split(",")[1]) == 50.0

    # Check mapped BBs are scaled down
    bb0_line = [l for l in out_lines if "bb_0" in l][0]
    d_bb0 = float(bb0_line.split(",")[1])
    assert 0.0 < d_bb0 <= 10.0


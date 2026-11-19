"""Unit tests for Milestone 5: Target-conditioned ranker and PU learning trainer."""
from __future__ import annotations

from pathlib import Path
import pytest
import torch

from target_graph.models.losses import NonNegativePULoss, UnbiasedPULoss, pairwise_ranking_loss
from target_graph.llvm.mapping import BasicBlockMapper
from target_graph.training.datasets import TargetGraphDataset, TargetGraphSample
from target_graph.training.metrics import compute_mrr, compute_pu_metrics, compute_recall_at_k
from target_graph.training.trainer import TargetConditionedModel, TargetGraphTrainer, TrainerConfig


def test_pu_losses():
    pos_scores = torch.tensor([2.0, 1.5, 0.8], requires_grad=True)
    unlabeled_scores = torch.tensor([-0.5, 0.2, -1.0, 1.2], requires_grad=True)

    # nnPU loss
    nn_pu = NonNegativePULoss(prior=0.1)
    loss = nn_pu(pos_scores, unlabeled_scores)
    assert loss.item() >= 0.0
    loss.backward()
    assert pos_scores.grad is not None
    assert unlabeled_scores.grad is not None

    # Test clamping when neg_risk < 0
    # Artificially high scores for unlabeled so neg_loss_u is very low, pos_scores low so neg_loss_p high
    pos_low = torch.tensor([-5.0], requires_grad=True)
    unl_high = torch.tensor([5.0], requires_grad=True)
    loss_clamped = nn_pu(pos_low, unl_high)
    assert loss_clamped.item() >= 0.0


def test_pairwise_ranking_loss():
    pos = torch.tensor([2.0, 3.0])
    neg = torch.tensor([0.1, -1.0])
    loss = pairwise_ranking_loss(pos, neg)
    assert loss.item() > 0.0

    # If neg > pos, loss should be higher
    pos_worse = torch.tensor([0.1, -1.0])
    neg_worse = torch.tensor([2.0, 3.0])
    loss_higher = pairwise_ranking_loss(pos_worse, neg_worse)
    assert loss_higher.item() > loss.item()


def test_metrics_computation():
    pos_scores = torch.tensor([2.0, 3.0, 1.5])
    unl_scores = torch.tensor([-1.0, 0.0, -0.5])
    m = compute_pu_metrics(pos_scores, unl_scores)
    assert m["pu_auc"] == 1.0
    assert m["score_margin"] > 0.0

    scores = torch.tensor([0.1, 0.9, 0.2, 0.8])
    pos_mask = torch.tensor([False, True, False, False])
    recall = compute_recall_at_k(scores, pos_mask, k_values=[1, 2])
    assert recall["recall@1"] == 1.0
    assert compute_mrr(scores, pos_mask) == 1.0


def test_trainer_end_to_end_pu_mode(tmp_path: Path):
    num_nodes = 10
    in_dim = 64
    hidden_dim = 32
    dist_embed_dim = 8

    # Create dummy sample
    x = torch.randn(num_nodes, in_dim)
    edge_index = torch.tensor([
        [0, 1, 2, 3, 4, 5, 6, 7, 8],
        [1, 2, 3, 4, 5, 6, 7, 8, 9],
    ], dtype=torch.long)
    edge_type = torch.zeros(9, dtype=torch.long)
    dist_buckets = torch.tensor([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], dtype=torch.long)

    pos_mask = torch.zeros(num_nodes, dtype=torch.bool)
    pos_mask[0] = True
    pos_mask[1] = True

    unlabeled_mask = torch.ones(num_nodes, dtype=torch.bool)
    unlabeled_mask[0] = False
    unlabeled_mask[1] = False

    neg_mask = torch.zeros(num_nodes, dtype=torch.bool)  # |N_t| = 0

    sample = TargetGraphSample(
        case_id="dummy_case",
        target_bb="bb_0",
        x=x,
        edge_index=edge_index,
        edge_type=edge_type,
        dist_buckets=dist_buckets,
        target_idx=0,
        pos_mask=pos_mask,
        unlabeled_mask=unlabeled_mask,
        neg_mask=neg_mask,
        bb_to_idx={f"bb_{i}": i for i in range(num_nodes)},
        idx_to_bb=[f"bb_{i}" for i in range(num_nodes)],
    )

    config = TrainerConfig(
        in_dim=in_dim,
        hidden_dim=hidden_dim,
        num_layers=2,
        dist_embed_dim=dist_embed_dim,
        mlp_hidden_dim=32,
        learning_rate=1e-3,
        device="cpu",
    )

    trainer = TargetGraphTrainer(config, num_relations=9)
    dataset = TargetGraphDataset([sample])

    # Train step
    loss, metrics = trainer.train_step(sample)
    assert loss > 0.0
    assert metrics["mode"] == "nnPU_learning"

    # Train epoch
    epoch_res = trainer.train_epoch(dataset)
    assert "epoch_loss" in epoch_res
    assert "epoch_pu_auc" in epoch_res

    # Evaluate
    eval_res = trainer.evaluate_sample(sample)
    assert "pu_auc" in eval_res
    assert "mrr" in eval_res

    # Checkpoint save & load
    ckpt_file = tmp_path / "model.pt"
    trainer.save_checkpoint(ckpt_file)
    assert ckpt_file.exists()

    trainer_loaded = TargetGraphTrainer(config, num_relations=9)
    trainer_loaded.load_checkpoint(ckpt_file)


def test_trainer_switches_to_pairwise_when_negatives_exist():
    num_nodes = 4
    x = torch.randn(num_nodes, 16)
    edge_index = torch.tensor([[0, 1], [1, 2]], dtype=torch.long)
    edge_type = torch.zeros(2, dtype=torch.long)
    dist_buckets = torch.zeros(num_nodes, dtype=torch.long)

    pos_mask = torch.tensor([True, False, False, False])
    unlabeled_mask = torch.tensor([False, True, False, False])
    neg_mask = torch.tensor([False, False, True, True])  # |N_t| > 0

    sample = TargetGraphSample(
        case_id="test_with_negs",
        target_bb="bb_0",
        x=x,
        edge_index=edge_index,
        edge_type=edge_type,
        dist_buckets=dist_buckets,
        target_idx=0,
        pos_mask=pos_mask,
        unlabeled_mask=unlabeled_mask,
        neg_mask=neg_mask,
        bb_to_idx={f"bb_{i}": i for i in range(num_nodes)},
        idx_to_bb=[f"bb_{i}" for i in range(num_nodes)],
    )

    config = TrainerConfig(in_dim=16, hidden_dim=8, num_layers=1, dist_embed_dim=4, mlp_hidden_dim=8, device="cpu")
    trainer = TargetGraphTrainer(config, num_relations=9)

    loss, metrics = trainer.train_step(sample)
    assert loss > 0.0
    assert metrics["mode"] == "pairwise_ranking"


def test_cache_missing_strict_failure(tmp_path: Path):
    """Verify that from_case_directory fails loudly when cache is missing and allow_mock=False."""
    case_dir = Path("/home/user/workspace/nycu-dissertation/target_graph/cases/cJSON-1.7.8_cJSON_CVE-2019-1010239")
    if not case_dir.exists():
        pytest.skip("Case directory not found")

    empty_cache = tmp_path / "empty_cache"
    empty_cache.mkdir()

    valid_target_bb = list(BasicBlockMapper(case_dir / "bb_map.jsonl").bb_records.keys())[0]

    # Must raise FileNotFoundError in production mode
    with pytest.raises(FileNotFoundError, match="CRITICAL ERROR"):
        TargetGraphDataset.from_case_directory(
            case_dir=case_dir,
            case_id="cJSON-1.7.8_cJSON_CVE-2019-1010239",
            target_bb=valid_target_bb,
            cache_dir=empty_cache,
            allow_mock=False,
        )

    # Must succeed when allow_mock=True
    sample = TargetGraphDataset.from_case_directory(
        case_dir=case_dir,
        case_id="cJSON-1.7.8_cJSON_CVE-2019-1010239",
        target_bb=valid_target_bb,
        cache_dir=empty_cache,
        allow_mock=True,
        allow_unverified_labels=True,  # Smoke test only; not validated supervision.
    )
    assert sample.x is not None


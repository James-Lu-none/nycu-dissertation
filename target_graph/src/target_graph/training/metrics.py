"""Evaluation metrics for target-conditioned ranking and PU learning."""
from __future__ import annotations

from typing import Dict, List, Set, Union
import numpy as np
import torch
from sklearn.metrics import roc_auc_score


def compute_pu_metrics(
    pos_scores: torch.Tensor,
    unlabeled_scores: torch.Tensor,
) -> Dict[str, float]:
    """Compute PU learning evaluation metrics.
    
    Args:
        pos_scores: [P] model scores for positive BBs
        unlabeled_scores: [U] model scores for unlabeled BBs
        
    Returns:
        Dictionary of metrics: pu_auc, pos_mean, unl_mean, score_margin
    """
    p_np = pos_scores.detach().cpu().numpy()
    u_np = unlabeled_scores.detach().cpu().numpy()

    if len(p_np) == 0 or len(u_np) == 0:
        return {"pu_auc": 0.5, "pos_mean": 0.0, "unl_mean": 0.0, "score_margin": 0.0}

    y_true = np.concatenate([np.ones_like(p_np), np.zeros_like(u_np)])
    y_score = np.concatenate([p_np, u_np])

    try:
        auc = float(roc_auc_score(y_true, y_score))
    except Exception:
        auc = 0.5

    pos_mean = float(np.mean(p_np))
    unl_mean = float(np.mean(u_np))
    margin = pos_mean - unl_mean

    return {
        "pu_auc": auc,
        "pos_mean": pos_mean,
        "unl_mean": unl_mean,
        "score_margin": margin,
    }


def compute_recall_at_k(
    scores: torch.Tensor,
    pos_mask: torch.Tensor,
    k_values: List[int] = (10, 50, 100),
) -> Dict[str, float]:
    """Compute Recall@K: fraction of positive nodes retrieved in top-K predictions."""
    if pos_mask.sum() == 0:
        return {f"recall@{k}": 0.0 for k in k_values}

    sorted_indices = torch.argsort(scores, descending=True)
    num_positives = int(pos_mask.sum().item())
    results = {}

    for k in k_values:
        top_k = sorted_indices[:min(k, len(sorted_indices))]
        hits = int(pos_mask[top_k].sum().item())
        results[f"recall@{k}"] = hits / max(1, num_positives)

    return results


def compute_mrr(
    scores: torch.Tensor,
    pos_mask: torch.Tensor,
) -> float:
    """Compute Mean Reciprocal Rank (MRR) of the highest-ranked positive node."""
    if pos_mask.sum() == 0:
        return 0.0

    sorted_indices = torch.argsort(scores, descending=True)
    for rank, idx in enumerate(sorted_indices, start=1):
        if pos_mask[idx]:
            return 1.0 / rank

    return 0.0


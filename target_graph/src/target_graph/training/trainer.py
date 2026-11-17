"""Target-conditioned R-GCN ranker trainer with PU learning and margin ranking."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import torch
import torch.nn as nn
from torch.optim import AdamW

from target_graph.models.heads import TargetConditionedRanker
from target_graph.models.losses import NonNegativePULoss, pairwise_ranking_loss
from target_graph.models.rgcn import ProgramRGCN
from target_graph.training.datasets import TargetGraphDataset, TargetGraphSample
from target_graph.training.metrics import compute_mrr, compute_pu_metrics, compute_recall_at_k

logger = logging.getLogger(__name__)


@dataclass
class TrainerConfig:
    in_dim: int = 3584
    hidden_dim: int = 256
    num_layers: int = 2
    dropout: float = 0.1
    dist_embed_dim: int = 32
    mlp_hidden_dim: int = 128
    learning_rate: float = 1e-4
    weight_decay: float = 1e-4
    epochs: int = 10
    grad_clip: float = 1.0
    pu_prior: float = 0.05
    device: str = "cuda" if torch.cuda.is_available() else "cpu"


class TargetConditionedModel(nn.Module):
    """Unified model combining ProgramRGCN and TargetConditionedRanker."""

    def __init__(self, config: TrainerConfig, num_relations: int = 9) -> None:
        super().__init__()
        self.config = config
        self.rgcn = ProgramRGCN(
            in_dim=config.in_dim,
            hidden_dim=config.hidden_dim,
            num_layers=config.num_layers,
            num_relations=num_relations,
            dropout=config.dropout,
        )
        self.ranker = TargetConditionedRanker(
            node_dim=config.hidden_dim,
            dist_embed_dim=config.dist_embed_dim,
            mlp_hidden_dim=config.mlp_hidden_dim,
            dropout=config.dropout,
        )

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor,
        target_idx: int,
        dist_buckets: torch.Tensor,
    ) -> torch.Tensor:
        """Computes target-conditioned scores s_theta(i | t) for all nodes i."""
        h = self.rgcn(x, edge_index, edge_type)
        h_target = h[target_idx:target_idx + 1]
        scores = self.ranker(h, h_target, dist_buckets)
        return scores


class TargetGraphTrainer:
    """Trainer orchestrating optimization, PU learning, evaluation, and checkpointing."""

    def __init__(
        self,
        config: TrainerConfig,
        model: Optional[TargetConditionedModel] = None,
        num_relations: int = 9,
    ) -> None:
        self.config = config
        self.device = torch.device(config.device)
        self.model = model or TargetConditionedModel(config, num_relations=num_relations)
        self.model.to(self.device)

        self.optimizer = AdamW(
            self.model.parameters(),
            lr=config.learning_rate,
            weight_decay=config.weight_decay,
        )
        self.pu_loss_fn = NonNegativePULoss(prior=config.pu_prior)

    def train_step(self, sample: TargetGraphSample) -> Tuple[Optional[float], Dict[str, Any]]:
        if sample.num_positives == 0:
            logger.warning(f"Skipping training step for {sample.case_id}: |P_t| == 0 (no positive supervision)")
            return None, {"mode": "skipped_no_positives", "case_id": sample.case_id}

        self.model.train()
        self.optimizer.zero_grad()

        x = sample.x.to(self.device)
        edge_index = sample.edge_index.to(self.device)
        edge_type = sample.edge_type.to(self.device)
        dist_buckets = sample.dist_buckets.to(self.device)
        target_idx = sample.target_idx

        scores = self.model(x, edge_index, edge_type, target_idx, dist_buckets)

        pos_scores = scores[sample.pos_mask.to(self.device)]
        unlabeled_scores = scores[sample.unlabeled_mask.to(self.device)]
        neg_scores = scores[sample.neg_mask.to(self.device)]

        if sample.num_negatives > 0:
            loss = pairwise_ranking_loss(pos_scores, neg_scores)
            mode = "pairwise_ranking"
        else:
            loss = self.pu_loss_fn(pos_scores, unlabeled_scores)
            mode = "nnPU_learning"

        loss.backward()
        nn.utils.clip_grad_norm_(self.model.parameters(), self.config.grad_clip)
        self.optimizer.step()

        metrics = compute_pu_metrics(pos_scores, unlabeled_scores)
        metrics["loss"] = float(loss.item())
        metrics["mode"] = mode

        return float(loss.item()), metrics

    def evaluate_sample(self, sample: TargetGraphSample) -> Dict[str, float]:
        self.model.eval()
        with torch.no_grad():
            x = sample.x.to(self.device)
            edge_index = sample.edge_index.to(self.device)
            edge_type = sample.edge_type.to(self.device)
            dist_buckets = sample.dist_buckets.to(self.device)
            target_idx = sample.target_idx

            scores = self.model(x, edge_index, edge_type, target_idx, dist_buckets)

            pos_scores = scores[sample.pos_mask.to(self.device)]
            unlabeled_scores = scores[sample.unlabeled_mask.to(self.device)]

            metrics = compute_pu_metrics(pos_scores, unlabeled_scores)
            recall = compute_recall_at_k(scores.cpu(), sample.pos_mask, k_values=[10, 50])
            mrr = compute_mrr(scores.cpu(), sample.pos_mask)

            metrics.update(recall)
            metrics["mrr"] = mrr
            return metrics

    def train_epoch(self, dataset: TargetGraphDataset) -> Dict[str, float]:
        total_loss = 0.0
        stepped = 0
        all_metrics: List[Dict[str, float]] = []

        for sample in dataset:
            loss_val, m = self.train_step(sample)
            if loss_val is not None:
                total_loss += loss_val
                stepped += 1
                all_metrics.append(m)

        avg_loss = total_loss / max(1, stepped)
        avg_auc = sum(m.get("pu_auc", 0.5) for m in all_metrics) / max(1, stepped)
        avg_margin = sum(m.get("score_margin", 0.0) for m in all_metrics) / max(1, stepped)

        return {
            "epoch_loss": avg_loss,
            "epoch_pu_auc": avg_auc,
            "epoch_score_margin": avg_margin,
            "active_targets": stepped,
        }

    def save_checkpoint(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "model_state": self.model.state_dict(),
                "optimizer_state": self.optimizer.state_dict(),
                "config": self.config,
            },
            p,
        )

    def load_checkpoint(self, path: Path | str) -> None:
        checkpoint = torch.load(path, map_location=self.device, weights_only=False)
        self.model.load_state_dict(checkpoint["model_state"])
        self.optimizer.load_state_dict(checkpoint["optimizer_state"])

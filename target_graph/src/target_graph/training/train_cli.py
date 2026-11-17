"""CLI runner for training target-conditioned R-GCN ranker."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List
import yaml
import torch

from target_graph.training.datasets import TargetGraphDataset, TargetGraphSample
from target_graph.training.trainer import TargetConditionedModel, TargetGraphTrainer, TrainerConfig


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Target-Conditioned R-GCN Ranker.")
    parser.add_argument("--config", default="configs/train/rgcn.yaml", help="Path to training config YAML")
    parser.add_argument("--epochs", type=int, default=None, help="Override number of training epochs")
    parser.add_argument("--cases", nargs="*", default=None, help="Optional case IDs to train on")
    parser.add_argument("--checkpoint-dir", default=None, help="Directory to save model checkpoints")
    parser.add_argument("--allow-mock", action="store_true", help="Allow mock pseudo-embeddings if cache is missing (tests only)")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[3]
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = root / config_path

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    model_cfg = cfg.get("model", {})
    train_cfg = cfg.get("train", {})

    epochs = args.epochs or train_cfg.get("epochs", 10)
    ckpt_dir = Path(args.checkpoint_dir or train_cfg.get("checkpoint_dir", "checkpoints/rgcn"))
    if not ckpt_dir.is_absolute():
        ckpt_dir = root / ckpt_dir
    ckpt_dir.mkdir(parents=True, exist_ok=True)

    trainer_cfg = TrainerConfig(
        in_dim=model_cfg.get("in_dim", 3584),
        hidden_dim=model_cfg.get("hidden_dim", 256),
        num_layers=model_cfg.get("num_layers", 2),
        dropout=model_cfg.get("dropout", 0.1),
        dist_embed_dim=model_cfg.get("dist_embed_dim", 32),
        mlp_hidden_dim=model_cfg.get("mlp_hidden_dim", 128),
        learning_rate=train_cfg.get("learning_rate", 1e-4),
        weight_decay=train_cfg.get("weight_decay", 1e-4),
        epochs=epochs,
        grad_clip=train_cfg.get("grad_clip", 1.0),
        pu_prior=train_cfg.get("pu_prior", 0.05),
    )

    # Load cases from cases.yaml or audit report
    audit_report = root / "reports" / "label_yield_audit.json"
    if not audit_report.exists():
        raise FileNotFoundError(f"Audit report not found at {audit_report}. Run label audit first.")

    with open(audit_report, "r", encoding="utf-8") as f:
        records = json.load(f)

    samples: List[TargetGraphSample] = []
    cases_dir = root / "cases"

    for r in records:
        case_id = r["case_id"]
        if args.cases and case_id not in args.cases:
            continue
        cdir = cases_dir / case_id
        target_bb = r["target_bb"]
        print(f"Loading graph sample for {case_id} (Target BB: {target_bb})...")
        sample = TargetGraphDataset.from_case_directory(
            case_dir=cdir,
            case_id=case_id,
            target_bb=target_bb,
            cache_dir=root / "cache" / "embeddings",
            allow_mock=args.allow_mock,
        )
        samples.append(sample)
        print(f"  Nodes: {sample.num_nodes}, Positives (P_t): {sample.num_positives}, Unlabeled: {sample.num_unlabeled}, Negatives: {sample.num_negatives}")

    dataset = TargetGraphDataset(samples)
    trainer = TargetGraphTrainer(trainer_cfg)

    print(f"\nStarting training for {epochs} epochs on {len(dataset)} targets...")
    for epoch in range(1, epochs + 1):
        epoch_metrics = trainer.train_epoch(dataset)
        print(
            f"Epoch {epoch:02d}/{epochs:02d} | "
            f"Loss: {epoch_metrics['epoch_loss']:.4f} | "
            f"PU-AUC: {epoch_metrics['epoch_pu_auc']:.4f} | "
            f"Score Margin: {epoch_metrics['epoch_score_margin']:+.4f}"
        )

    # Save final model checkpoint
    final_ckpt = ckpt_dir / "rgcn_ranker_final.pt"
    trainer.save_checkpoint(final_ckpt)
    print(f"\nModel checkpoint successfully saved to {final_ckpt}")

    # Evaluate all targets
    print("\n--- Final Evaluation Summary ---")
    for sample in dataset:
        eval_metrics = trainer.evaluate_sample(sample)
        print(
            f"[{sample.case_id}] "
            f"PU-AUC: {eval_metrics['pu_auc']:.4f} | "
            f"Recall@10: {eval_metrics.get('recall@10', 0.0):.4f} | "
            f"MRR: {eval_metrics['mrr']:.4f} | "
            f"Margin: {eval_metrics['score_margin']:+.4f}"
        )


if __name__ == "__main__":
    main()


"""CLI for model evaluation and AFLGo distance scaling adapter."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List
import yaml
import torch

from target_graph.analysis.aflgo_scaler import AFLGoDistanceScaler
from target_graph.training.datasets import TargetGraphDataset, TargetGraphSample
from target_graph.training.trainer import TargetConditionedModel, TargetGraphTrainer, TrainerConfig


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate target-conditioned model and scale AFLGo distances.")
    parser.add_argument("--config", default="configs/train/rgcn.yaml", help="Config file")
    parser.add_argument("--checkpoint", default="checkpoints/rgcn/rgcn_ranker_final.pt", help="Model checkpoint")
    parser.add_argument("--eta", type=float, default=1.0, help="AFLGo scaling factor eta")
    parser.add_argument("--output-dir", default="reports", help="Directory for evaluation reports")
    parser.add_argument("--allow-mock", action="store_true", help="Allow mock pseudo-embeddings if cache is missing (tests only)")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[3]
    ckpt_path = Path(args.checkpoint)
    if not ckpt_path.is_absolute():
        ckpt_path = root / ckpt_path

    if not ckpt_path.exists():
        raise FileNotFoundError(f"Model checkpoint not found at {ckpt_path}")

    with open(root / args.config, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    model_cfg = cfg.get("model", {})
    trainer_cfg = TrainerConfig(
        in_dim=model_cfg.get("in_dim", 3584),
        hidden_dim=model_cfg.get("hidden_dim", 256),
        num_layers=model_cfg.get("num_layers", 2),
        dropout=model_cfg.get("dropout", 0.1),
        dist_embed_dim=model_cfg.get("dist_embed_dim", 32),
        mlp_hidden_dim=model_cfg.get("mlp_hidden_dim", 128),
        device="cpu",
    )

    trainer = TargetGraphTrainer(trainer_cfg)
    trainer.load_checkpoint(ckpt_path)
    model = trainer.model

    scaler = AFLGoDistanceScaler(model=model, eta=args.eta, device="cpu")

    audit_report = root / "reports" / "label_yield_audit.json"
    with open(audit_report, "r", encoding="utf-8") as f:
        records = json.load(f)

    out_dir = root / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary_records: List[Dict[str, Any]] = []

    print("\n=======================================================")
    print("  Target-Conditioned Graph Learning Evaluation & Scaling")
    print("=======================================================\n")

    for r in records:
        case_id = r["case_id"]
        cdir = root / "cases" / case_id
        target_bb = r["target_bb"]

        sample = TargetGraphDataset.from_case_directory(
            case_dir=cdir,
            case_id=case_id,
            target_bb=target_bb,
            cache_dir=root / "cache" / "embeddings",
            allow_mock=args.allow_mock,
        )

        eval_res = trainer.evaluate_sample(sample)

        # Generate mock or read existing distance.cfg.txt for scaling
        dist_file = cdir / "distance.cfg.txt"
        if not dist_file.exists():
            # Build baseline distance file from execution distances
            with open(dist_file, "w", encoding="utf-8") as f:
                for idx, bb in enumerate(sample.idx_to_bb):
                    bucket_val = float(sample.dist_buckets[idx].item())
                    f.write(f"{bb},{bucket_val:.1f}\n")

        scaled_file = cdir / "distance.scaled.cfg.txt"
        scale_metrics = scaler.scale_distance_file(dist_file, scaled_file, sample)

        case_summary = {
            "case_id": case_id,
            "project": r["project"],
            "cve": r["cve"],
            "target_bb": target_bb,
            "num_nodes": sample.num_nodes,
            "num_positives": sample.num_positives,
            "pu_auc": eval_res["pu_auc"],
            "recall@10": eval_res.get("recall@10", 0.0),
            "recall@50": eval_res.get("recall@50", 0.0),
            "mrr": eval_res["mrr"],
            "score_margin": eval_res["score_margin"],
            "aflgo_eta": args.eta,
            "mean_orig_dist": scale_metrics.mean_orig_distance,
            "mean_scaled_dist": scale_metrics.mean_scaled_distance,
            "pos_dist_reduction_pct": scale_metrics.pos_distance_reduction_pct,
            "unl_dist_reduction_pct": scale_metrics.unl_distance_reduction_pct,
        }
        summary_records.append(case_summary)

        print(
            f"[{case_id}]\n"
            f"  PU-AUC: {eval_res['pu_auc']:.4f} | Margin: {eval_res['score_margin']:+.4f} | MRR: {eval_res['mrr']:.4f}\n"
            f"  Distance Scaling (eta={args.eta}): Pos Reduction: {scale_metrics.pos_distance_reduction_pct:.2f}% | "
            f"Unl Reduction: {scale_metrics.unl_distance_reduction_pct:.2f}%\n"
        )

    # Export report JSON and Markdown
    json_path = out_dir / "evaluation_summary.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary_records, f, indent=2)

    md_path = out_dir / "evaluation_summary.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Target-Conditioned Ranker Evaluation & AFLGo Distance Scaling Summary\n\n")
        f.write(f"**Model Checkpoint**: `{ckpt_path.name}`  \n")
        f.write(f"**AFLGo Scaling Factor (eta)**: `{args.eta}`  \n\n")
        f.write("| Case ID | Target BB | |V| | |P_t| | PU-AUC | Margin | MRR | P_t Dist Reduc | U_t Dist Reduc |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for s in summary_records:
            f.write(
                f"| `{s['case_id']}` | `{s['target_bb'][:8]}...` | {s['num_nodes']} | {s['num_positives']} | "
                f"{s['pu_auc']:.4f} | {s['score_margin']:+.4f} | {s['mrr']:.4f} | "
                f"{s['pos_dist_reduction_pct']:.2f}% | {s['unl_dist_reduction_pct']:.2f}% |\n"
            )

    print(f"[SUCCESS] Reports generated:\n  - {json_path}\n  - {md_path}")


if __name__ == "__main__":
    main()


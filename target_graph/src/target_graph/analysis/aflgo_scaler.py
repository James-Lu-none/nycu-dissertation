"""AFLGo distance scaling adapter with bounded positive GNN guidance."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import numpy as np
import torch

from target_graph.llvm.mapping import BasicBlockMapper
from target_graph.training.datasets import TargetGraphSample
from target_graph.training.trainer import TargetConditionedModel, TrainerConfig


@dataclass
class ScalerMetrics:
    total_entries: int
    mapped_entries: int
    unmapped_entries: int
    mean_orig_distance: float
    mean_scaled_distance: float
    pos_mean_orig: float
    pos_mean_scaled: float
    unl_mean_orig: float
    unl_mean_scaled: float
    pos_distance_reduction_pct: float
    unl_distance_reduction_pct: float


class AFLGoDistanceScaler:
    """Computes bounded distance scaling D' = D_AFLGo * g_eta(s_theta).
    
    Guarantees:
    1. g_eta(s) > 0 and bounded in [exp(-eta), 1] for all real scores.
    2. Strictly preserves original distance D_AFLGo when eta == 0 or for unmapped nodes.
    3. D' <= D_AFLGo for all nodes, prioritizing target-conditioned candidate paths.
    """

    def __init__(
        self,
        model: TargetConditionedModel,
        eta: float = 1.0,
        device: str = "cpu",
    ) -> None:
        if eta < 0.0:
            raise ValueError(f"Scaling factor eta must be non-negative, got {eta}")
        self.model = model
        self.eta = eta
        self.device = torch.device(device)
        self.model.to(self.device)
        self.model.eval()

    def g_eta(self, score: torch.Tensor) -> torch.Tensor:
        """Bounded positive scaling factor: g_eta(s) = exp(-eta * sigmoid(s))."""
        prob = torch.sigmoid(score)
        return torch.exp(-self.eta * prob)

    def compute_bb_scores(self, sample: TargetGraphSample) -> Dict[str, float]:
        """Compute s_theta(i | t) for all basic blocks in sample."""
        with torch.no_grad():
            x = sample.x.to(self.device)
            edge_index = sample.edge_index.to(self.device)
            edge_type = sample.edge_type.to(self.device)
            dist_buckets = sample.dist_buckets.to(self.device)
            target_idx = sample.target_idx

            scores = self.model(x, edge_index, edge_type, target_idx, dist_buckets)
            scores_np = scores.cpu().numpy()

        return {sample.idx_to_bb[i]: float(scores_np[i]) for i in range(len(sample.idx_to_bb))}

    def scale_distance_file(
        self,
        input_distance_file: Path | str,
        output_distance_file: Path | str,
        sample: TargetGraphSample,
        bb_mapper: Optional[BasicBlockMapper] = None,
    ) -> ScalerMetrics:
        """Scale AFLGo distance.cfg.txt file and write distance.scaled.cfg.txt."""
        in_path = Path(input_distance_file)
        out_path = Path(output_distance_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        bb_scores = self.compute_bb_scores(sample)
        
        # Precompute positive and unlabeled BB sets
        pos_bbs = {sample.idx_to_bb[i] for i in range(sample.num_nodes) if sample.pos_mask[i]}
        unl_bbs = {sample.idx_to_bb[i] for i in range(sample.num_nodes) if sample.unlabeled_mask[i]}

        orig_dists: List[float] = []
        scaled_dists: List[float] = []
        pos_orig: List[float] = []
        pos_scaled: List[float] = []
        unl_orig: List[float] = []
        unl_scaled: List[float] = []

        mapped_count = 0
        unmapped_count = 0

        scaled_lines: List[str] = []

        with open(in_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    scaled_lines.append(line)
                    continue

                parts = line_str.split(",")
                if len(parts) != 2:
                    scaled_lines.append(line)
                    continue

                bb_key, dist_str = parts[0].strip(), parts[1].strip()
                try:
                    orig_dist = float(dist_str)
                except ValueError:
                    scaled_lines.append(line)
                    continue

                # Find matching BB in graph
                matched_bb: Optional[str] = None
                if bb_key in bb_scores:
                    matched_bb = bb_key
                elif bb_mapper is not None:
                    # Attempt mapping by location if key has file:line format
                    if ":" in bb_key:
                        file_part, line_part = bb_key.rsplit(":", 1)
                        if line_part.isdigit():
                            cand_bbs = bb_mapper.map_source_location(file_part, int(line_part))
                            if cand_bbs and cand_bbs[0] in bb_scores:
                                matched_bb = cand_bbs[0]

                if matched_bb is not None:
                    score = bb_scores[matched_bb]
                    scale_val = float(self.g_eta(torch.tensor(score)).item())
                    scaled_dist = orig_dist * scale_val
                    mapped_count += 1

                    if matched_bb in pos_bbs:
                        pos_orig.append(orig_dist)
                        pos_scaled.append(scaled_dist)
                    elif matched_bb in unl_bbs:
                        unl_orig.append(orig_dist)
                        unl_scaled.append(scaled_dist)
                else:
                    # Unmapped: preserve exact original distance
                    scaled_dist = orig_dist
                    unmapped_count += 1

                orig_dists.append(orig_dist)
                scaled_dists.append(scaled_dist)
                scaled_lines.append(f"{bb_key},{scaled_dist:.6f}\n")

        with open(out_path, "w", encoding="utf-8") as f:
            f.writelines(scaled_lines)

        mean_orig = float(np.mean(orig_dists)) if orig_dists else 0.0
        mean_scaled = float(np.mean(scaled_dists)) if scaled_dists else 0.0
        p_mean_orig = float(np.mean(pos_orig)) if pos_orig else 0.0
        p_mean_scaled = float(np.mean(pos_scaled)) if pos_scaled else 0.0
        u_mean_orig = float(np.mean(unl_orig)) if unl_orig else 0.0
        u_mean_scaled = float(np.mean(unl_scaled)) if unl_scaled else 0.0

        p_reduc = ((p_mean_orig - p_mean_scaled) / p_mean_orig * 100.0) if p_mean_orig > 0 else 0.0
        u_reduc = ((u_mean_orig - u_mean_scaled) / u_mean_orig * 100.0) if u_mean_orig > 0 else 0.0

        return ScalerMetrics(
            total_entries=len(orig_dists),
            mapped_entries=mapped_count,
            unmapped_entries=unmapped_count,
            mean_orig_distance=mean_orig,
            mean_scaled_distance=mean_scaled,
            pos_mean_orig=p_mean_orig,
            pos_mean_scaled=p_mean_scaled,
            unl_mean_orig=u_mean_orig,
            unl_mean_scaled=u_mean_scaled,
            pos_distance_reduction_pct=p_reduc,
            unl_distance_reduction_pct=u_reduc,
        )


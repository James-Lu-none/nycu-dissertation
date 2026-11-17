"""Graph dataset loading, partition mapping, and batching for training."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import pandas as pd
import torch
from torch.utils.data import Dataset

from target_graph.analysis.exec_distance import get_execution_distance_buckets
from target_graph.embeddings.cache import EmbeddingCache
from target_graph.graphs.loader import load_program_graph_to_pyg
from target_graph.labels.slicing import SlicePartition, partition_target_candidates
from target_graph.llvm.mapping import BasicBlockMapper
from target_graph.tracing.symbolizer import trace_to_basic_blocks


@dataclass
class TargetGraphSample:
    case_id: str
    target_bb: str
    x: torch.Tensor              # [N, in_dim]
    edge_index: torch.Tensor     # [2, E]
    edge_type: torch.Tensor      # [E]
    dist_buckets: torch.Tensor   # [N]
    target_idx: int
    pos_mask: torch.Tensor       # [N] bool
    unlabeled_mask: torch.Tensor # [N] bool
    neg_mask: torch.Tensor       # [N] bool
    bb_to_idx: Dict[str, int]
    idx_to_bb: List[str]

    @property
    def num_nodes(self) -> int:
        return self.x.size(0)

    @property
    def num_positives(self) -> int:
        return int(self.pos_mask.sum().item())

    @property
    def num_unlabeled(self) -> int:
        return int(self.unlabeled_mask.sum().item())

    @property
    def num_negatives(self) -> int:
        return int(self.neg_mask.sum().item())


class TargetGraphDataset(Dataset):
    """Dataset of target-conditioned program graphs."""

    def __init__(
        self,
        samples: List[TargetGraphSample],
    ) -> None:
        self.samples = samples

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> TargetGraphSample:
        return self.samples[idx]

    @classmethod
    def from_case_directory(
        cls,
        case_dir: Path | str,
        case_id: str,
        target_bb: str,
        cache_dir: Optional[Path | str] = None,
        layer_idx: int = 14,
        feature_dim: int = 3584,
        allow_mock: bool = False,
    ) -> TargetGraphSample:
        case_dir = Path(case_dir)
        parquet_dir = case_dir / "parquet"
        nodes_df = pd.read_parquet(parquet_dir / "nodes.parquet")
        edges_df = pd.read_parquet(parquet_dir / "edges.parquet")

        # Load PyG graph structure
        pyg_data, bb_to_idx = load_program_graph_to_pyg(parquet_dir, include_reverse_edges=False)
        num_nodes = pyg_data.num_nodes
        ordered_bbs = [None] * num_nodes
        for bb, idx in bb_to_idx.items():
            ordered_bbs[idx] = bb

        if target_bb not in bb_to_idx:
            raise ValueError(f"Target BB {target_bb} not found in graph nodes for {case_id}")
        target_idx = bb_to_idx[target_bb]

        # Load embeddings from cache if available, or generate deterministic features
        x = None
        if cache_dir:
            cache = EmbeddingCache(cache_dir)
            if cache.has_valid_cache(case_id, layer_idx, expected_dim=feature_dim):
                embs, missing, _ = cache.load(case_id, layer_idx)
                x = torch.zeros(num_nodes, feature_dim, dtype=torch.float32)
                for bb, idx in bb_to_idx.items():
                    if bb in embs:
                        x[idx] = embs[bb]
        
        if x is None:
            if not allow_mock:
                raise FileNotFoundError(
                    f"CRITICAL ERROR: Valid Qwen embedding cache not found for case '{case_id}' "
                    f"(layer {layer_idx}, dim {feature_dim}) in '{cache_dir}'. Fallback to mock "
                    f"embeddings is forbidden in production mode. Pass allow_mock=True or run extraction."
                )
            # Deterministic pseudo-embeddings seeded by BB ID for reproducibility
            x = torch.zeros(num_nodes, feature_dim, dtype=torch.float32)
            for bb, idx in bb_to_idx.items():
                seed = int(bb[:8], 16) if len(bb) >= 8 else idx
                gen = torch.Generator().manual_seed(seed)
                x[idx] = torch.randn(feature_dim, generator=gen)

        # Compute execution distance buckets
        dist_buckets = get_execution_distance_buckets(
            target_bb=target_bb,
            all_bbs_ordered=ordered_bbs,
            edges_df=edges_df,
        )

        # Symbolize trace and compute candidate partition
        mapper = BasicBlockMapper(case_dir / "bb_map.jsonl")
        trace_file = case_dir / "trace_crash.txt"
        
        inst_binary = None
        for cand in case_dir.glob("*_inst"):
            inst_binary = cand
            break
        if not inst_binary:
            inst_binary = case_dir / "test_target"

        executed_bbs = set()
        if trace_file.exists() and inst_binary.exists():
            try:
                executed_bbs = trace_to_basic_blocks(trace_file, inst_binary, mapper)
            except Exception:
                executed_bbs = {target_bb}
        else:
            executed_bbs = {target_bb}

        all_bbs_set = set(ordered_bbs)
        partition = partition_target_candidates(
            all_bbs=all_bbs_set,
            executed_trace_bbs=executed_bbs,
            edges_df=edges_df,
            target_bb=target_bb,
        )

        # Masks for P_t, U_t, N_t
        pos_mask = torch.zeros(num_nodes, dtype=torch.bool)
        unlabeled_mask = torch.zeros(num_nodes, dtype=torch.bool)
        neg_mask = torch.zeros(num_nodes, dtype=torch.bool)

        for bb in partition.P_t:
            if bb in bb_to_idx:
                pos_mask[bb_to_idx[bb]] = True

        for bb in (partition.U_t | partition.C_t):
            if bb in bb_to_idx and not pos_mask[bb_to_idx[bb]]:
                unlabeled_mask[bb_to_idx[bb]] = True

        for bb in partition.N_t:
            if bb in bb_to_idx:
                neg_mask[bb_to_idx[bb]] = True

        return TargetGraphSample(
            case_id=case_id,
            target_bb=target_bb,
            x=x,
            edge_index=pyg_data.edge_index,
            edge_type=pyg_data.edge_type,
            dist_buckets=dist_buckets,
            target_idx=target_idx,
            pos_mask=pos_mask,
            unlabeled_mask=unlabeled_mask,
            neg_mask=neg_mask,
            bb_to_idx=bb_to_idx,
            idx_to_bb=ordered_bbs,
        )


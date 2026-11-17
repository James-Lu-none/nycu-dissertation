"""Load Parquet tables into PyG Data objects with categorical relation IDs."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple
import pandas as pd
import torch
from torch_geometric.data import Data

from .relations import CANONICAL_RELATION_TO_ID, NUM_CANONICAL_RELATIONS, NUM_MESSAGE_RELATIONS


def load_program_graph_to_pyg(
    graph_dir: Path,
    node_features: Optional[torch.Tensor] = None,
    include_reverse_edges: bool = False,
) -> Tuple[Data, Dict[str, int]]:
    """Load nodes.parquet and edges.parquet from graph_dir into a PyG Data object.
    
    Args:
        graph_dir: Path containing nodes.parquet and edges.parquet.
        node_features: Optional tensor of shape [num_nodes, feature_dim]. If None, zero features.
        include_reverse_edges: If True, adds REV_<relation> edges to message passing.
        
    Returns:
        (pyg_data, bb_to_idx_mapping)
    """
    nodes_df = pd.read_parquet(graph_dir / "nodes.parquet")
    edges_df = pd.read_parquet(graph_dir / "edges.parquet")

    # Map bb_id to index 0..N-1
    bb_list = nodes_df["bb_id"].tolist()
    bb_to_idx = {bb: i for i, bb in enumerate(bb_list)}
    num_nodes = len(bb_list)

    src_indices = [bb_to_idx[s] for s in edges_df["src_bb"]]
    dst_indices = [bb_to_idx[d] for d in edges_df["dst_bb"]]
    relation_types = edges_df["relation_id"].tolist()

    if include_reverse_edges:
        # Add reverse edges with relation_id + NUM_CANONICAL_RELATIONS
        rev_src = dst_indices[:]
        rev_dst = src_indices[:]
        rev_rel = [r + NUM_CANONICAL_RELATIONS for r in relation_types]

        src_indices.extend(rev_src)
        dst_indices.extend(rev_dst)
        relation_types.extend(rev_rel)

    edge_index = torch.tensor([src_indices, dst_indices], dtype=torch.long)
    edge_type = torch.tensor(relation_types, dtype=torch.long)

    if node_features is not None:
        if node_features.size(0) != num_nodes:
            raise ValueError(
                f"node_features size {node_features.size(0)} does not match node count {num_nodes}"
            )
        x = node_features
    else:
        # Placeholder node features if Qwen embeddings are cached separately
        x = torch.zeros((num_nodes, 1), dtype=torch.float32)

    data = Data(x=x, edge_index=edge_index, edge_type=edge_type, num_nodes=num_nodes)
    data.bb_ids = bb_list
    data.num_relations = NUM_MESSAGE_RELATIONS if include_reverse_edges else NUM_CANONICAL_RELATIONS

    return data, bb_to_idx


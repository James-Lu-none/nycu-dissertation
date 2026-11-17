"""Token offset alignment and Basic Block average pooling for LLVM IR nodes."""
from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple
import torch

from target_graph.graphs.schema import SourceSpan


def align_tokens_to_bbs(
    token_offsets: List[Tuple[int, int]],
    source_lines: List[str],
    bb_source_spans: Dict[str, List[SourceSpan]],
) -> Dict[str, List[int]]:
    """Map character offsets of tokens to Basic Block IDs based on source lines.
    
    Args:
        token_offsets: List of (char_start, char_end) for each token.
        source_lines: List of line strings in the function source.
        bb_source_spans: Mapping of bb_id -> list of SourceSpan (1-based line numbers).
        
    Returns:
        Mapping of bb_id -> list of token indices T_b.
    """
    import bisect

    line_starts: List[int] = []
    curr_char = 0
    for line in source_lines:
        line_starts.append(curr_char)
        curr_char += len(line)

    # Map each 1-based line to BB IDs
    line_to_bbs: Dict[int, Set[str]] = {}
    for bb_id, spans in bb_source_spans.items():
        for span in spans:
            for l in range(span.start_line, span.end_line + 1):
                if l not in line_to_bbs:
                    line_to_bbs[l] = set()
                line_to_bbs[l].add(bb_id)

    bb_to_tokens: Dict[str, List[int]] = {bb: [] for bb in bb_source_spans}

    for tok_idx, (tok_start, tok_end) in enumerate(token_offsets):
        line_no = bisect.bisect_right(line_starts, tok_start)
        candidate_bbs = line_to_bbs.get(line_no, set())
        if len(candidate_bbs) == 1:
            bb = next(iter(candidate_bbs))
            bb_to_tokens[bb].append(tok_idx)

    return bb_to_tokens


def pool_bb_embeddings(
    hidden_states: torch.Tensor,
    bb_to_tokens: Dict[str, List[int]],
    layer_idx: int = 14,
    feature_dim: int = 3584,
) -> Tuple[Dict[str, torch.Tensor], Dict[str, bool]]:
    """Pool token hidden states to Basic Block vectors x_b = mean_{k in T_b} H_{f, k}.
    
    Args:
        hidden_states: [num_layers, seq_len, hidden_dim]
        bb_to_tokens: bb_id -> list of token indices
        layer_idx: Selected transformer layer index (e.g. 7, 14, 21, 28)
        feature_dim: Expected hidden dimension (3584 for Qwen2.5-Coder-7B)
        
    Returns:
        (bb_embeddings, missing_mask):
            bb_embeddings: bb_id -> tensor of shape [feature_dim]
            missing_mask: bb_id -> bool (True if T_b is empty and feature was zero-masked)
    """
    layer_repr = hidden_states[layer_idx]  # [seq_len, hidden_dim]
    bb_embeddings: Dict[str, torch.Tensor] = {}
    missing_mask: Dict[str, bool] = {}

    for bb_id, tokens in bb_to_tokens.items():
        if tokens:
            tok_indices = torch.tensor(tokens, dtype=torch.long, device=layer_repr.device)
            bb_repr = layer_repr[tok_indices].mean(dim=0)
            bb_embeddings[bb_id] = bb_repr.detach().cpu()
            missing_mask[bb_id] = False
        else:
            # Missing source span or synthetic IR BB: zero tensor + mask
            bb_embeddings[bb_id] = torch.zeros(feature_dim, dtype=torch.float32)
            missing_mask[bb_id] = True

    return bb_embeddings, missing_mask


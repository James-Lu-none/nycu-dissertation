"""PoC-derived target label slicing and candidate partition."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import networkx as nx
import pandas as pd

from target_graph.graphs.relations import CANONICAL_RELATION_TO_ID


@dataclass
class SlicePartition:
    target_bb: str
    V: Set[str]                # Total program BBs
    E_t: Set[str]              # Deduplicated executed BBs in PoC trace
    S_t: Set[str]              # Static backward dependence slice rooted at target_bb (DDG_SSA, DDG_MEM, CDG, CALL, RETURN)
    R_t: Set[str] = field(default_factory=set)  # CFG execution reachability to target_bb (CFG + CALL/RETURN)
    P_t: Set[str] = field(init=False)  # Weak positives: E_t & S_t
    U_t: Set[str] = field(init=False)  # Unknown unexecuted: S_t - E_t
    C_t: Set[str] = field(init=False)  # Unknown executed non-slice: E_t - S_t
    N_t: Set[str] = field(default_factory=set)  # Independently qualified negatives

    def __post_init__(self) -> None:
        self.P_t = self.E_t & self.S_t
        self.U_t = self.S_t - self.E_t
        self.C_t = self.E_t - self.S_t

    @property
    def has_verified_negatives(self) -> bool:
        return len(self.N_t) > 0

    def summary(self) -> Dict[str, int]:
        return {
            "|V|": len(self.V),
            "|E_t|": len(self.E_t),
            "|S_t|": len(self.S_t),
            "|R_t|": len(self.R_t),
            "|P_t|": len(self.P_t),
            "|U_t|": len(self.U_t),
            "|C_t|": len(self.C_t),
            "|N_t|": len(self.N_t),
        }


def compute_static_backward_slice(
    edges_df: pd.DataFrame,
    target_bb: str,
    relation_filter: Optional[Set[int]] = None,
    max_depth: Optional[int] = None,
) -> Set[str]:
    """Compute conservative static backward data/control dependence slice rooted at target_bb.
    
    Includes DDG_SSA, DDG_MEM, CDG, and CALL/RETURN transitions.
    Strictly excludes CFG transitions (CFG edges are control-flow paths, NOT dependencies).
    """
    if relation_filter is None:
        # Backward data and control dependence relations only
        relation_filter = {
            CANONICAL_RELATION_TO_ID["DDG_SSA"],
            CANONICAL_RELATION_TO_ID["DDG_MEM"],
            CANONICAL_RELATION_TO_ID["CDG"],
            CANONICAL_RELATION_TO_ID["CALL"],
            CANONICAL_RELATION_TO_ID["RETURN"],
        }

    # Build reverse dependency graph (dst -> src)
    g = nx.DiGraph()
    filtered = edges_df[edges_df["relation_id"].isin(relation_filter)]
    for _, row in filtered.iterrows():
        # Edge in slice: dst_bb depends on src_bb, so to trace backward from target,
        # we traverse from target along reverse edges: dst_bb -> src_bb
        g.add_edge(row["dst_bb"], row["src_bb"])

    if target_bb not in g:
        return {target_bb}

    # BFS from target_bb in the backward direction
    if max_depth is not None:
        lengths = nx.single_source_shortest_path_length(g, target_bb, cutoff=max_depth)
        return set(lengths.keys())
    else:
        return set(nx.descendants(g, target_bb)) | {target_bb}


def compute_execution_reachability(
    edges_df: pd.DataFrame,
    target_bb: str,
    direction: str = "backward",
    max_depth: Optional[int] = None,
) -> Set[str]:
    """Compute CFG execution reachability (control-flow reachability to/from target_bb).
    
    Traverses strictly CFG edges (CFG_T, CFG_F, CFG_NEXT, CFG_OTHER) plus CALL/RETURN transitions.
    """
    cfg_relations = {
        CANONICAL_RELATION_TO_ID["CFG_T"],
        CANONICAL_RELATION_TO_ID["CFG_F"],
        CANONICAL_RELATION_TO_ID["CFG_NEXT"],
        CANONICAL_RELATION_TO_ID["CFG_OTHER"],
        CANONICAL_RELATION_TO_ID["CALL"],
        CANONICAL_RELATION_TO_ID["RETURN"],
    }
    g = nx.DiGraph()
    filtered = edges_df[edges_df["relation_id"].isin(cfg_relations)]
    for _, row in filtered.iterrows():
        if direction == "backward":
            # Reverse edge: dst -> src so forward BFS from target finds all CFG predecessors
            g.add_edge(row["dst_bb"], row["src_bb"])
        else:
            g.add_edge(row["src_bb"], row["dst_bb"])

    if target_bb not in g:
        return {target_bb}

    if max_depth is not None:
        lengths = nx.single_source_shortest_path_length(g, target_bb, cutoff=max_depth)
        return set(lengths.keys())
    else:
        return set(nx.descendants(g, target_bb)) | {target_bb}


def partition_target_candidates(
    all_bbs: Set[str],
    executed_trace_bbs: List[str],
    edges_df: pd.DataFrame,
    target_bb: str,
    verified_negatives: Optional[Set[str]] = None,
) -> SlicePartition:
    """Construct rigorous candidate partition according to Section 5."""
    E_t = set(executed_trace_bbs)
    S_t = compute_static_backward_slice(edges_df, target_bb)
    R_t = compute_execution_reachability(edges_df, target_bb, direction="backward")
    N_t = verified_negatives if verified_negatives is not None else set()

    return SlicePartition(
        target_bb=target_bb,
        V=all_bbs,
        E_t=E_t,
        S_t=S_t,
        R_t=R_t,
        N_t=N_t,
    )

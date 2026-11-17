"""Target-Conditioned Program Graph Learning: Slicing and Candidate Partition.

Implements two decoupled analysis pipelines:
1. Target Dependency Backward Slice: S_dep(t) = BackwardSlice_{DDG+CDG}(t)
   Traversing strictly DDG_SSA, DDG_MEM, and CDG.
   Produces P_t^dep = E_t & S_dep(t) as target-specific weak positives.
   If interprocedural DDG across functions is incomplete, flags analysis_incomplete = True.

2. Execution Reachability: R_exec(t) = ReverseReachability_{ICFG}(t)
   Traversing directed CFG edges (CFG_T, CFG_F, CFG_NEXT, CFG_OTHER) and CALL/RETURN.
   Used for execution distance and reachability guidance (not for positive labels).

3. Legacy Slice Ablation: S_all_legacy(t)
   Traversing DDG_SSA, DDG_MEM, CDG, CALL, RETURN.
   Produces P_t^legacy = E_t & S_legacy(t).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import networkx as nx
import pandas as pd

from target_graph.graphs.relations import CANONICAL_RELATION_TO_ID


@dataclass
class SlicePartition:
    target_bb: str
    V: Set[str]                                       # Total program basic blocks
    E_t: Set[str]                                     # Deduplicated executed BBs in PoC trace
    S_dep: Set[str]                                   # Pure dependency backward slice (DDG_SSA, DDG_MEM, CDG)
    S_legacy: Set[str]                                # Legacy CFG/Call-inclusive slice (DDG + CDG + CALL + RETURN)
    R_exec: Set[str]                                  # ICFG Execution reachability to target_bb (CFG + CALL/RETURN)
    N_t: Set[str] = field(default_factory=set)        # Verified negatives (defaults to empty; unknown != negative)
    analysis_incomplete: bool = True                  # True when interprocedural parameter/return DDG is not fully resolved
    callsite_aware_pairing: bool = False              # True if ICFG reachability strictly pairs callsites

    # Semantic quality and supervision gating
    slice_quality: str = "UNKNOWN"                    # DEGENERATE_TARGET_ONLY, INSUFFICIENT_INTRA_ONLY, OVER_INCLUSIVE_MAY_ALIAS, ADEQUATE_INTRA_DEPENDENCY
    analysis_status: str = "incomplete"               # Detailed status of analysis completeness
    missing_fault_operands: bool = False              # True if fault instruction operands lack definitions in the slice
    supervision_suitability: str = "UNKNOWN"          # REJECT_DEGENERATE_TARGET_ONLY, REJECT_MISSING_OPERANDS, CAUTION_OVER_INCLUSIVE, ACCEPT_WITH_PU_LEARNING
    quality_rationale: str = ""
    diagnostics: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Three supervision label sets
    P_t_trace: Set[str] = field(init=False)           # P_t^trace = E_t
    P_t_legacy: Set[str] = field(init=False)          # P_t^legacy = E_t & S_legacy
    P_t_dep: Set[str] = field(init=False)             # P_t^dep = E_t & S_dep

    # Retention metrics
    retention_dep: float = field(init=False)          # |E_t & S_dep| / |E_t|
    retention_legacy: float = field(init=False)       # |E_t & S_legacy| / |E_t|

    # Verification flags
    fault_bb_in_trace: bool = field(init=False)
    fault_bb_in_dep_slice: bool = field(init=False)

    # Unknown / Candidate sets
    U_t_dep: Set[str] = field(init=False)             # S_dep - E_t
    C_t_dep: Set[str] = field(init=False)             # E_t - S_dep

    def __post_init__(self) -> None:
        self.P_t_trace = set(self.E_t)
        self.P_t_legacy = self.E_t & self.S_legacy
        self.P_t_dep = self.E_t & self.S_dep

        len_e = len(self.E_t)
        self.retention_dep = round(len(self.P_t_dep) / len_e, 6) if len_e > 0 else 0.0
        self.retention_legacy = round(len(self.P_t_legacy) / len_e, 6) if len_e > 0 else 0.0

        self.fault_bb_in_trace = self.target_bb in self.E_t
        self.fault_bb_in_dep_slice = self.target_bb in self.S_dep

        self.U_t_dep = self.S_dep - self.E_t
        self.C_t_dep = self.E_t - self.S_dep

    # Backwards compatibility properties
    @property
    def S_t(self) -> Set[str]:
        return self.S_dep

    @property
    def R_t(self) -> Set[str]:
        return self.R_exec

    @property
    def P_t(self) -> Set[str]:
        return self.P_t_dep

    @property
    def U_t(self) -> Set[str]:
        return self.U_t_dep

    @property
    def C_t(self) -> Set[str]:
        return self.C_t_dep

    @property
    def has_verified_negatives(self) -> bool:
        return len(self.N_t) > 0

    def summary(self) -> Dict[str, Any]:
        return {
            "|V|": len(self.V),
            "|E_t|": len(self.E_t),
            "|S_dep|": len(self.S_dep),
            "|S_legacy|": len(self.S_legacy),
            "|R_exec|": len(self.R_exec),
            "|P_t_dep|": len(self.P_t_dep),
            "|P_t_legacy|": len(self.P_t_legacy),
            "|P_t_trace|": len(self.P_t_trace),
            "retention_dep": self.retention_dep,
            "retention_legacy": self.retention_legacy,
            "fault_bb_in_trace": self.fault_bb_in_trace,
            "fault_bb_in_dep_slice": self.fault_bb_in_dep_slice,
            "analysis_incomplete": self.analysis_incomplete,
            "slice_quality": self.slice_quality,
            "analysis_status": self.analysis_status,
            "missing_fault_operands": self.missing_fault_operands,
            "supervision_suitability": self.supervision_suitability,
            "|N_t|": len(self.N_t),
        }


def compute_target_dependency_backward_slice(
    edges_df: pd.DataFrame,
    target_bb: str,
    relation_filter: Optional[Set[int]] = None,
    max_depth: Optional[int] = None,
) -> Set[str]:
    """Compute target dependency backward slice S_dep(t) = BackwardSlice_{DDG+CDG}(t).
    
    Reverse traversal strictly includes:
    - DDG_SSA (relation_id 4): SSA def-use dependencies
    - DDG_MEM (relation_id 5): memory dependencies
    - CDG (relation_id 6): control dependencies
    
    Strictly excludes CFG transitions and general CALL/RETURN transitions.
    Retains target_bb itself.
    """
    if relation_filter is None:
        relation_filter = {
            CANONICAL_RELATION_TO_ID["DDG_SSA"],
            CANONICAL_RELATION_TO_ID["DDG_MEM"],
            CANONICAL_RELATION_TO_ID["CDG"],
        }

    filtered = edges_df[edges_df["relation_id"].isin(relation_filter)]
    if filtered.empty:
        return {target_bb}

    # In our graph, src_bb -> dst_bb with DDG/CDG means dst_bb depends on src_bb.
    # To trace backward from target (finding definitions/predicates that target depends on),
    # reverse the edge direction: dst_bb -> src_bb.
    g = nx.from_pandas_edgelist(filtered, source="dst_bb", target="src_bb", create_using=nx.DiGraph)

    if target_bb not in g:
        return {target_bb}

    if max_depth is not None:
        lengths = nx.single_source_shortest_path_length(g, target_bb, cutoff=max_depth)
        return set(lengths.keys())
    else:
        return set(nx.descendants(g, target_bb)) | {target_bb}


def compute_static_backward_slice_legacy(
    edges_df: pd.DataFrame,
    target_bb: str,
    relation_filter: Optional[Set[int]] = None,
    max_depth: Optional[int] = None,
) -> Set[str]:
    """Legacy CFG/Call-inclusive slice ablation S_all_legacy(t).
    
    Traverses DDG_SSA, DDG_MEM, CDG, CALL, RETURN.
    """
    if relation_filter is None:
        relation_filter = {
            CANONICAL_RELATION_TO_ID["DDG_SSA"],
            CANONICAL_RELATION_TO_ID["DDG_MEM"],
            CANONICAL_RELATION_TO_ID["CDG"],
            CANONICAL_RELATION_TO_ID["CALL"],
            CANONICAL_RELATION_TO_ID["RETURN"],
        }

    filtered = edges_df[edges_df["relation_id"].isin(relation_filter)]
    if filtered.empty:
        return {target_bb}

    g = nx.from_pandas_edgelist(filtered, source="dst_bb", target="src_bb", create_using=nx.DiGraph)

    if target_bb not in g:
        return {target_bb}

    if max_depth is not None:
        lengths = nx.single_source_shortest_path_length(g, target_bb, cutoff=max_depth)
        return set(lengths.keys())
    else:
        return set(nx.descendants(g, target_bb)) | {target_bb}


def compute_static_backward_slice(
    edges_df: pd.DataFrame,
    target_bb: str,
    relation_filter: Optional[Set[int]] = None,
    max_depth: Optional[int] = None,
) -> Set[str]:
    """Default backward slice alias pointing to pure dependency backward slice S_dep."""
    return compute_target_dependency_backward_slice(
        edges_df=edges_df,
        target_bb=target_bb,
        relation_filter=relation_filter,
        max_depth=max_depth,
    )


def compute_execution_reachability(
    edges_df: pd.DataFrame,
    target_bb: str,
    direction: str = "backward",
    max_depth: Optional[int] = None,
) -> Set[str]:
    """Compute ICFG execution reachability R_exec(t).
    
    Traverses directed CFG edges (CFG_T, CFG_F, CFG_NEXT, CFG_OTHER) and CALL/RETURN.
    In backward direction, queries all basic blocks that can reach target_bb.
    Used for execution distance and AFLGo integration, NOT for positive labels.
    """
    cfg_relations = {
        CANONICAL_RELATION_TO_ID["CFG_T"],
        CANONICAL_RELATION_TO_ID["CFG_F"],
        CANONICAL_RELATION_TO_ID["CFG_NEXT"],
        CANONICAL_RELATION_TO_ID["CFG_OTHER"],
        CANONICAL_RELATION_TO_ID["CALL"],
        CANONICAL_RELATION_TO_ID["RETURN"],
    }
    filtered = edges_df[edges_df["relation_id"].isin(cfg_relations)]
    if filtered.empty:
        return {target_bb}

    if direction == "backward":
        # Reverse edge: dst -> src so forward search from target finds all predecessors that reach target
        g = nx.from_pandas_edgelist(filtered, source="dst_bb", target="src_bb", create_using=nx.DiGraph)
    else:
        g = nx.from_pandas_edgelist(filtered, source="src_bb", target="dst_bb", create_using=nx.DiGraph)

    if target_bb not in g:
        return {target_bb}

    if max_depth is not None:
        lengths = nx.single_source_shortest_path_length(g, target_bb, cutoff=max_depth)
        return set(lengths.keys())
    else:
        return set(nx.descendants(g, target_bb)) | {target_bb}


def trace_backward_slice_diagnostics(
    edges_df: pd.DataFrame,
    target_bb: str,
    relation_filter: Optional[Set[int]] = None,
    max_depth: Optional[int] = None,
) -> Dict[str, Dict[str, Any]]:
    """Compute detailed instruction/BB-level backward slice diagnostics.
    
    Returns a dictionary mapping each bb_id in the slice to:
    - distance: shortest hop count from target_bb in reverse dependency graph
    - reason: classification of inclusion reason (e.g. TARGET_SITE, DIRECT_OPERAND_DEF, DIRECT_CDG_PREDICATE, DIRECT_MEM_ALIAS, TRANSITIVE_DEP)
    - path: shortest dependency path from target_bb to this bb
    - path_relations: relation types along each hop of the path
    - incoming_relations: all relation types connecting this bb to any downstream bb in the slice
    """
    if relation_filter is None:
        relation_filter = {
            CANONICAL_RELATION_TO_ID["DDG_SSA"],
            CANONICAL_RELATION_TO_ID["DDG_MEM"],
            CANONICAL_RELATION_TO_ID["CDG"],
        }

    id_to_rel_name = {v: k for k, v in CANONICAL_RELATION_TO_ID.items()}
    filtered = edges_df[edges_df["relation_id"].isin(relation_filter)]
    if filtered.empty:
        return {
            target_bb: {
                "bb_id": target_bb,
                "distance": 0,
                "reason": "TARGET_SITE_ISOLATED",
                "path": [target_bb],
                "path_relations": [],
                "incoming_relations": [],
            }
        }

    # Pre-filter to slice members to keep the diagnostic graph small and fast
    slice_bbs = compute_target_dependency_backward_slice(
        edges_df=filtered,
        target_bb=target_bb,
        relation_filter=relation_filter,
        max_depth=max_depth,
    )
    if not slice_bbs or target_bb not in slice_bbs:
        return {
            target_bb: {
                "bb_id": target_bb,
                "distance": 0,
                "reason": "TARGET_SITE_ISOLATED",
                "path": [target_bb],
                "path_relations": [],
                "incoming_relations": [],
            }
        }

    sub_edges = filtered[filtered["dst_bb"].isin(slice_bbs) & filtered["src_bb"].isin(slice_bbs)]

    # In graph: src -> dst (dst depends on src).
    # In reversed graph: dst -> src (find what target depends on).
    g = nx.DiGraph()
    has_status = "analysis_status" in sub_edges.columns
    for row in sub_edges.itertuples(index=False):
        u = row.dst_bb
        v = row.src_bb
        rel = id_to_rel_name.get(row.relation_id, str(row.relation_id))
        status = getattr(row, "analysis_status", "verified") if has_status else "verified"
        if not g.has_edge(u, v):
            g.add_edge(u, v, relations=[rel], statuses=[status])
        else:
            g[u][v]["relations"].append(rel)
            g[u][v]["statuses"].append(status)

    if target_bb not in g:
        return {
            target_bb: {
                "bb_id": target_bb,
                "distance": 0,
                "reason": "TARGET_SITE_ISOLATED",
                "path": [target_bb],
                "path_relations": [],
                "incoming_relations": [],
            }
        }

    paths = nx.single_source_shortest_path(g, target_bb, cutoff=max_depth)
    lengths = nx.single_source_shortest_path_length(g, target_bb, cutoff=max_depth)

    diagnostics: Dict[str, Dict[str, Any]] = {}
    for bb, dist in lengths.items():
        p = paths[bb]
        path_rels: List[str] = []
        for i in range(len(p) - 1):
            edge_data = g.get_edge_data(p[i], p[i+1])
            path_rels.append(",".join(edge_data.get("relations", [])))

        if dist == 0:
            reason = "TARGET_SITE"
        elif dist == 1:
            edge_data = g.get_edge_data(target_bb, bb)
            rels = edge_data.get("relations", [])
            if "DDG_SSA" in rels:
                reason = "DIRECT_OPERAND_DEF"
            elif "CDG" in rels:
                reason = "DIRECT_CDG_PREDICATE"
            elif "DDG_MEM" in rels:
                reason = "DIRECT_MEM_ALIAS"
            else:
                reason = f"DIRECT_{rels[0]}"
        else:
            reason = f"TRANSITIVE_DEP_{path_rels[-1]}"

        incoming_rels = []
        if bb in g:
            for pred in g.predecessors(bb):
                if pred in paths:
                    incoming_rels.extend(g[pred][bb].get("relations", []))

        diagnostics[bb] = {
            "bb_id": bb,
            "distance": dist,
            "reason": reason,
            "path": p,
            "path_relations": path_rels,
            "incoming_relations": list(set(incoming_rels)),
        }

    return diagnostics


def assess_slice_quality(
    partition: SlicePartition,
    edges_df: pd.DataFrame,
    nodes_df: Optional[pd.DataFrame] = None,
) -> Dict[str, Any]:
    """Assess semantic quality of target backward slice and determine supervision suitability.
    
    Evaluates:
    1. Degenerate target-only slice (|S_dep| == 1).
    2. Missing fault operands: target BB has no incoming DDG_SSA/DDG_MEM inside slice.
    3. Runaway expansion: MayAlias dominates the slice (e.g. jhead).
    4. Interprocedural status.
    """
    tbb = partition.target_bb
    s_dep = partition.S_dep
    num_s = len(s_dep)
    
    in_dep_edges = edges_df[
        (edges_df["dst_bb"] == tbb) & 
        (edges_df["src_bb"].isin(s_dep)) & 
        (edges_df["relation_id"].isin({4, 5, 6}))
    ]
    has_operand_def = not in_dep_edges[in_dep_edges["relation_id"].isin({4, 5})].empty
    has_predicate = not in_dep_edges[in_dep_edges["relation_id"] == 6].empty
    
    mem_edges = edges_df[
        (edges_df["dst_bb"].isin(s_dep)) & 
        (edges_df["src_bb"].isin(s_dep)) & 
        (edges_df["relation_id"] == 5)
    ]
    num_may_alias = len(mem_edges[mem_edges.get("analysis_status", "") == "may"]) if not mem_edges.empty else 0
    total_dep_edges = len(edges_df[
        (edges_df["dst_bb"].isin(s_dep)) & 
        (edges_df["src_bb"].isin(s_dep)) & 
        (edges_df["relation_id"].isin({4, 5, 6}))
    ])

    if num_s == 1:
        slice_quality = "DEGENERATE_TARGET_ONLY"
        analysis_status = "missing_interprocedural_dependencies"
        missing_fault_operands = True
        supervision_suitability = "REJECT_DEGENERATE_TARGET_ONLY"
        quality_rationale = (
            "Target backward slice contains ONLY the target basic block itself (|S_dep| = 1). "
            "Zero operand definitions, allocations, or branch predicates were captured because "
            "fault operands originate from caller parameters or unanalyzed cross-function memory."
        )
    elif not has_operand_def and num_s <= 5:
        slice_quality = "INSUFFICIENT_INTRA_ONLY"
        analysis_status = "missing_caller_operand_definitions"
        missing_fault_operands = True
        supervision_suitability = "REJECT_MISSING_OPERANDS"
        quality_rationale = (
            f"Target backward slice is severely undersized (|S_dep| = {num_s}) and missing fault operand definitions. "
            "Captured blocks are only local control structures (e.g. switch or null checks), while the "
            "fault-inducing data was passed via function arguments from unlinked callers."
        )
    elif partition.retention_dep > 0.90 and num_may_alias > 0.5 * max(1, total_dep_edges):
        slice_quality = "OVER_INCLUSIVE_MAY_ALIAS"
        analysis_status = "pervasive_may_alias_expansion"
        missing_fault_operands = False
        supervision_suitability = "CAUTION_USE_MUST_ALIAS_OR_CDG_ONLY"
        quality_rationale = (
            f"Slice expanded to {partition.retention_dep:.1%} of trace due to pervasive MayAlias memory edges. "
            "BasicAA conservative assumptions connect arbitrary pointer stores across the function. "
            "Recommended to filter by MUST-alias or restrict to SSA+CDG."
        )
    else:
        slice_quality = "ADEQUATE_INTRA_DEPENDENCY"
        analysis_status = "intraprocedural_complete_interprocedural_partial"
        missing_fault_operands = False
        supervision_suitability = "ACCEPT_WITH_PU_LEARNING"
        quality_rationale = (
            f"Slice captures substantive intra-procedural SSA definitions and controlling predicates (|S_dep| = {num_s}). "
            "Suitable for target-conditioned positive supervision under Non-negative PU Learning."
        )

    return {
        "slice_quality": slice_quality,
        "analysis_status": analysis_status,
        "missing_fault_operands": missing_fault_operands,
        "has_operand_def": has_operand_def,
        "has_predicate": has_predicate,
        "supervision_suitability": supervision_suitability,
        "quality_rationale": quality_rationale,
    }


def compute_slicing_ablation(
    edges_df: pd.DataFrame,
    target_bb: str,
    executed_trace_bbs: Set[str] | List[str],
) -> Dict[str, Any]:
    """Compute comparative slicing ablation across different relation subsets."""
    et = set(executed_trace_bbs)
    len_e = len(et)
    
    s_legacy = compute_static_backward_slice_legacy(edges_df, target_bb)
    s_ssa = compute_target_dependency_backward_slice(edges_df, target_bb, relation_filter={CANONICAL_RELATION_TO_ID["DDG_SSA"]})
    s_ssa_cdg = compute_target_dependency_backward_slice(edges_df, target_bb, relation_filter={
        CANONICAL_RELATION_TO_ID["DDG_SSA"],
        CANONICAL_RELATION_TO_ID["CDG"],
    })
    s_all_dep = compute_target_dependency_backward_slice(edges_df, target_bb, relation_filter={
        CANONICAL_RELATION_TO_ID["DDG_SSA"],
        CANONICAL_RELATION_TO_ID["DDG_MEM"],
        CANONICAL_RELATION_TO_ID["CDG"],
    })
    
    must_edges = edges_df[
        (edges_df["relation_id"] != CANONICAL_RELATION_TO_ID["DDG_MEM"]) | 
        (edges_df.get("analysis_status", "") == "must")
    ]
    s_must_mem_cdg = compute_target_dependency_backward_slice(must_edges, target_bb, relation_filter={
        CANONICAL_RELATION_TO_ID["DDG_SSA"],
        CANONICAL_RELATION_TO_ID["DDG_MEM"],
        CANONICAL_RELATION_TO_ID["CDG"],
    })
    
    r_exec = compute_execution_reachability(edges_df, target_bb, direction="backward")

    return {
        "num_executed_Et": len_e,
        "slice_legacy": len(s_legacy),
        "retention_legacy": round(len(et & s_legacy) / len_e, 6) if len_e > 0 else 0.0,
        "slice_ssa_only": len(s_ssa),
        "retention_ssa_only": round(len(et & s_ssa) / len_e, 6) if len_e > 0 else 0.0,
        "slice_ssa_cdg": len(s_ssa_cdg),
        "retention_ssa_cdg": round(len(et & s_ssa_cdg) / len_e, 6) if len_e > 0 else 0.0,
        "slice_must_mem_cdg": len(s_must_mem_cdg),
        "retention_must_mem_cdg": round(len(et & s_must_mem_cdg) / len_e, 6) if len_e > 0 else 0.0,
        "slice_all_dep": len(s_all_dep),
        "retention_all_dep": round(len(et & s_all_dep) / len_e, 6) if len_e > 0 else 0.0,
        "num_reachable_exec": len(r_exec),
    }


def partition_target_candidates(
    all_bbs: Set[str],
    executed_trace_bbs: List[str] | Set[str],
    edges_df: pd.DataFrame,
    target_bb: str,
    verified_negatives: Optional[Set[str]] = None,
    analysis_incomplete: bool = True,
) -> SlicePartition:
    """Construct rigorous candidate partition according to Section 5 and decoupled dependency slice.
    
    Computes:
    - S_dep: pure dependency backward slice (DDG_SSA, DDG_MEM, CDG)
    - S_legacy: legacy CFG/Call-inclusive slice
    - R_exec: ICFG reachability to target_bb
    - P_t_dep, P_t_legacy, P_t_trace
    - Diagnostics & Slice Quality Assessment
    """
    E_t = set(executed_trace_bbs)
    S_dep = compute_target_dependency_backward_slice(edges_df, target_bb)
    S_legacy = compute_static_backward_slice_legacy(edges_df, target_bb)
    R_exec = compute_execution_reachability(edges_df, target_bb, direction="backward")
    N_t = verified_negatives if verified_negatives is not None else set()

    diagnostics = trace_backward_slice_diagnostics(edges_df, target_bb)

    partition = SlicePartition(
        target_bb=target_bb,
        V=all_bbs,
        E_t=E_t,
        S_dep=S_dep,
        S_legacy=S_legacy,
        R_exec=R_exec,
        N_t=N_t,
        analysis_incomplete=analysis_incomplete,
    )

    quality_info = assess_slice_quality(partition, edges_df)
    partition.slice_quality = quality_info["slice_quality"]
    partition.analysis_status = quality_info["analysis_status"]
    partition.missing_fault_operands = quality_info["missing_fault_operands"]
    partition.supervision_suitability = quality_info["supervision_suitability"]
    partition.quality_rationale = quality_info["quality_rationale"]
    partition.diagnostics = diagnostics

    return partition

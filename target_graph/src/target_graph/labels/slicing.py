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
from typing import Any, Dict, List, Optional, Set
import networkx as nx
import pandas as pd

from target_graph.graphs.relations import CANONICAL_RELATION_TO_ID


@dataclass
class SlicePartition:
    target_bb: str
    V: Set[str]                                       # Total program basic blocks
    E_t: Set[str]                                     # Deduplicated executed BBs in PoC trace
    S_dep: Set[str]                                   # Pure intraprocedural dependency backward slice (DDG_SSA, DDG_MEM, CDG)
    S_interproc: Set[str] = field(default_factory=set)# Interprocedural SDG slice (DDG + CDG + PARAM_IN + PARAM_OUT + CALLSITE_SUMMARY)
    S_legacy: Set[str] = field(default_factory=set)   # Legacy CFG/Call-inclusive slice (DDG + CDG + CALL + RETURN)
    R_exec: Set[str] = field(default_factory=set)     # ICFG Execution reachability to target_bb (CFG + CALL/RETURN)
    N_t: Set[str] = field(default_factory=set)        # Verified negatives (defaults to empty; unknown != negative)
    analysis_incomplete: bool = True                  # True when interprocedural parameter/return DDG is not fully resolved
    callsite_aware_pairing: bool = False              # True if ICFG reachability strictly pairs callsites

    # Semantic quality and supervision gating
    slice_quality: str = "UNKNOWN"                    # DEGENERATE_TARGET_ONLY, INTERPROCEDURAL_INCOMPLETE, OVER_INCLUSIVE_MAY_ALIAS, LOCAL_DEPENDENCY_VALIDATED, SUPERVISION_VALIDATED
    analysis_status: str = "incomplete"               # Detailed status of analysis completeness
    missing_fault_operands: bool = False              # True if fault instruction operands lack definitions in the slice
    fault_operand_coverage: Optional[float] = None               # Ratio of fault operands covered by definitions in slice
    supervision_suitability: str = "UNKNOWN"          # REJECT_DEGENERATE_TARGET_ONLY, REJECT_INCOMPLETE_DEPENDENCY, FILTER_REQUIRED_MUST_MEM_OR_CDG, ACCEPT_LOCAL_ONLY, ACCEPT_AS_SUPERVISION
    quality_rationale: str = ""
    diagnostics: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Three supervision label sets
    P_t_trace: Set[str] = field(init=False)           # P_t^trace = E_t
    P_t_legacy: Set[str] = field(init=False)          # P_t^legacy = E_t & S_legacy
    P_t_dep: Set[str] = field(init=False)             # P_t^dep = E_t & S_dep
    P_t_interproc: Set[str] = field(init=False)       # P_t^interproc = E_t & S_interproc

    # Retention metrics
    retention_dep: float = field(init=False)          # |E_t & S_dep| / |E_t|
    retention_interproc: float = field(init=False)    # |E_t & S_interproc| / |E_t|
    retention_legacy: float = field(init=False)       # |E_t & S_legacy| / |E_t|

    # Verification flags
    fault_bb_in_trace: bool = field(init=False)
    fault_bb_in_dep_slice: bool = field(init=False)

    # Unknown / Candidate sets
    U_t_dep: Set[str] = field(init=False)             # S_dep - E_t
    C_t_dep: Set[str] = field(init=False)             # E_t - S_dep

    def __post_init__(self) -> None:
        if not self.S_interproc:
            self.S_interproc = set(self.S_dep)
        self.P_t_trace = set(self.E_t)
        self.P_t_legacy = self.E_t & self.S_legacy
        self.P_t_dep = self.E_t & self.S_dep
        self.P_t_interproc = self.E_t & self.S_interproc

        len_e = len(self.E_t)
        self.retention_dep = round(len(self.P_t_dep) / len_e, 6) if len_e > 0 else 0.0
        self.retention_interproc = round(len(self.P_t_interproc) / len_e, 6) if len_e > 0 else 0.0
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
            "|S_interproc|": len(self.S_interproc),
            "|S_legacy|": len(self.S_legacy),
            "|R_exec|": len(self.R_exec),
            "|P_t_dep|": len(self.P_t_dep),
            "|P_t_interproc|": len(self.P_t_interproc),
            "|P_t_legacy|": len(self.P_t_legacy),
            "|P_t_trace|": len(self.P_t_trace),
            "retention_dep": self.retention_dep,
            "retention_interproc": self.retention_interproc,
            "retention_legacy": self.retention_legacy,
            "fault_bb_in_trace": self.fault_bb_in_trace,
            "fault_bb_in_dep_slice": self.fault_bb_in_dep_slice,
            "analysis_incomplete": self.analysis_incomplete,
            "slice_quality": self.slice_quality,
            "analysis_status": self.analysis_status,
            "missing_fault_operands": self.missing_fault_operands,
            "fault_operand_coverage": self.fault_operand_coverage,
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


def compute_interprocedural_backward_slice(
    edges_df: pd.DataFrame,
    target_bb: str,
    relation_filter: Optional[Set[int]] = None,
    max_depth: Optional[int] = None,
) -> Set[str]:
    """Compute exploratory interprocedural *candidate* backward reachability.
    
    Traverses intra-procedural dependencies (DDG_SSA, DDG_MEM, CDG)
    plus SDG interprocedural parameter and summary edges:
    - PARAM_IN (relation_id 9): Caller argument def -> Callee formal parameter
    - PARAM_OUT (relation_id 10): Callee return -> Caller receiving use
    - CALLSITE_SUMMARY (relation_id 11): Actual-in -> actual-out at callsite
    
    Strictly excludes unconstrained ICFG CFG edges and general CALL/RETURN edges.
    IMPORTANT: PARAM_IN/OUT are currently BB-level candidates, not verified
    formal/actual operand-level edges or context-sensitive SDG summaries.
    Do NOT use this result as validated supervision.
    """
    if relation_filter is None:
        relation_filter = {
            CANONICAL_RELATION_TO_ID["DDG_SSA"],
            CANONICAL_RELATION_TO_ID["DDG_MEM"],
            CANONICAL_RELATION_TO_ID["CDG"],
            CANONICAL_RELATION_TO_ID.get("PARAM_IN", 9),
            CANONICAL_RELATION_TO_ID.get("PARAM_OUT", 10),
            CANONICAL_RELATION_TO_ID.get("CALLSITE_SUMMARY", 11),
        }

    return compute_target_dependency_backward_slice(
        edges_df=edges_df,
        target_bb=target_bb,
        relation_filter=relation_filter,
        max_depth=max_depth,
    )


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
                reason = "DIRECT_BB_SSA_EDGE"
            elif "CDG" in rels:
                reason = "DIRECT_CDG_PREDICATE"
            elif "DDG_MEM" in rels:
                reason = "DIRECT_MEM_ALIAS_CANDIDATE"
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
    """Conservative quality gate, *not* a fault-operand provenance validator.

    Basic-block incoming DDG edges do not identify individual fault operands,
    memory reaching definitions or callsite-sensitive value flow. In the
    absence of instruction-level provenance evidence, coverage is UNKNOWN
    (None), never inferred as 100% from a single incoming edge.
    """
    s_dep = partition.S_dep
    mem_edges = edges_df[
        (edges_df["src_bb"].isin(s_dep))
        & (edges_df["dst_bb"].isin(s_dep))
        & (edges_df["relation_id"] == CANONICAL_RELATION_TO_ID["DDG_MEM"])
    ]
    has_may_alias = (
        "analysis_status" in mem_edges.columns
        and mem_edges["analysis_status"].eq("may").any()
    )
    if len(s_dep) <= 1:
        quality = "DEGENERATE_TARGET_ONLY"
        status = "target_only_no_provenance"
        suitability = "REJECT_DEGENERATE_TARGET_ONLY"
        rationale = "Only the target basic block is available; no operand provenance established."
    elif partition.retention_dep > 0.90 and has_may_alias:
        quality = "OVER_INCLUSIVE_MAY_ALIAS"
        status = "may_alias_candidate_expansion"
        suitability = "FILTER_REQUIRED_MUST_MEM_OR_CDG"
        rationale = "High retention with MayAlias candidates; dependency precision unverified."
    else:
        quality = "PROVENANCE_UNVERIFIED"
        status = "instruction_level_fault_operand_evidence_missing"
        suitability = "REJECT_UNVERIFIED_PROVENANCE"
        rationale = (
            "BB-level DDG/CDG/candidate PARAM edges cannot establish instruction-level "
            "fault operand coverage. No verified operand provenance supplied."
        )
    return {
        "slice_quality": quality,
        "analysis_status": status,
        "missing_fault_operands": True,  # missing verification evidence; not a proof of missing dataflow
        "fault_operand_coverage": None,
        "has_operand_def": False,        # unknown at operand granularity
        "has_predicate": False,          # unknown at instruction granularity
        "supervision_suitability": suitability,
        "quality_rationale": rationale,
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

    s_interproc = compute_interprocedural_backward_slice(edges_df, target_bb)
    r_exec = compute_execution_reachability(edges_df, target_bb, direction="backward")

    in_dep_edges = edges_df[
        (edges_df["dst_bb"] == target_bb) & 
        (edges_df["relation_id"].isin({4, 5}))
    ]
    fault_operand_coverage = None  # Not computable from BB-level incoming edges

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
        "slice_interprocedural": len(s_interproc),
        "retention_interprocedural": round(len(et & s_interproc) / len_e, 6) if len_e > 0 else 0.0,
        "fault_operand_coverage": fault_operand_coverage,
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
    - S_interproc: interprocedural SDG slice
    - S_legacy: legacy CFG/Call-inclusive slice
    - R_exec: ICFG reachability to target_bb
    - P_t_dep, P_t_interproc, P_t_legacy, P_t_trace
    - Diagnostics & Slice Quality Assessment
    """
    E_t = set(executed_trace_bbs)
    S_dep = compute_target_dependency_backward_slice(edges_df, target_bb)
    S_interproc = compute_interprocedural_backward_slice(edges_df, target_bb)
    S_legacy = compute_static_backward_slice_legacy(edges_df, target_bb)
    R_exec = compute_execution_reachability(edges_df, target_bb, direction="backward")
    N_t = verified_negatives if verified_negatives is not None else set()

    diagnostics = trace_backward_slice_diagnostics(edges_df, target_bb)

    partition = SlicePartition(
        target_bb=target_bb,
        V=all_bbs,
        E_t=E_t,
        S_dep=S_dep,
        S_interproc=S_interproc,
        S_legacy=S_legacy,
        R_exec=R_exec,
        N_t=N_t,
        analysis_incomplete=analysis_incomplete,
    )

    quality_info = assess_slice_quality(partition, edges_df)
    partition.slice_quality = quality_info["slice_quality"]
    partition.analysis_status = quality_info["analysis_status"]
    partition.missing_fault_operands = quality_info["missing_fault_operands"]
    partition.fault_operand_coverage = quality_info["fault_operand_coverage"]
    partition.supervision_suitability = quality_info["supervision_suitability"]
    partition.quality_rationale = quality_info["quality_rationale"]
    partition.diagnostics = diagnostics

    return partition

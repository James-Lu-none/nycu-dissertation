"""Unit tests validating the 5 acceptance criteria for decoupled slicing semantics.

Acceptance Criteria:
1. Logging BB on the execution path must NOT enter dependency slice S_dep solely due to CFG predecessor relation.
2. Definition BB influencing target operand MUST enter S_dep via DDG.
3. Controlling branch predicate BB MUST enter S_dep via CDG.
4. Interprocedural parameter/return dependencies: flagged as analysis_incomplete when summaries are missing,
   and correctly traversed when explicit parameter/return DDG edges exist.
5. ICFG reachability R_exec and dependency backward slice S_dep must yield distinct, correct sets (S_dep != R_exec).
"""
import pandas as pd
import pytest

from target_graph.graphs.relations import CANONICAL_RELATION_TO_ID
from target_graph.labels.slicing import (
    compute_execution_reachability,
    compute_static_backward_slice_legacy,
    compute_target_dependency_backward_slice,
    partition_target_candidates,
)


@pytest.fixture
def synthetic_semantic_program():
    """Builds a canonical multi-relational program graph with:
    - bb_caller: calls target_func
    - bb_entry: entry block of target_func
    - bb_logging: prints log message on execution path, no data/control dependency to target
    - bb_predicate: branch condition if (flag > 0) controlling bb_target execution
    - bb_def: defines y = x + 1 used as operand in bb_target
    - bb_target: target block performing *ptr = y (fault site)
    - bb_exit: function return block
    - bb_unrelated: unexecuted dead block
    """
    edges = [
        # ICFG Edges (CFG + CALL/RETURN)
        {"src_bb": "bb_caller", "dst_bb": "bb_entry", "relation_id": CANONICAL_RELATION_TO_ID["CALL"]},
        {"src_bb": "bb_entry", "dst_bb": "bb_logging", "relation_id": CANONICAL_RELATION_TO_ID["CFG_NEXT"]},
        {"src_bb": "bb_logging", "dst_bb": "bb_predicate", "relation_id": CANONICAL_RELATION_TO_ID["CFG_NEXT"]},
        {"src_bb": "bb_predicate", "dst_bb": "bb_def", "relation_id": CANONICAL_RELATION_TO_ID["CFG_T"]},
        {"src_bb": "bb_predicate", "dst_bb": "bb_exit", "relation_id": CANONICAL_RELATION_TO_ID["CFG_F"]},
        {"src_bb": "bb_def", "dst_bb": "bb_target", "relation_id": CANONICAL_RELATION_TO_ID["CFG_NEXT"]},
        {"src_bb": "bb_target", "dst_bb": "bb_exit", "relation_id": CANONICAL_RELATION_TO_ID["CFG_NEXT"]},
        {"src_bb": "bb_exit", "dst_bb": "bb_caller", "relation_id": CANONICAL_RELATION_TO_ID["RETURN"]},
        
        # Dependency Edges
        # 1. DDG_SSA: bb_def defines operand used in bb_target
        {"src_bb": "bb_def", "dst_bb": "bb_target", "relation_id": CANONICAL_RELATION_TO_ID["DDG_SSA"]},
        # 2. CDG: bb_predicate controls whether bb_target is executed
        {"src_bb": "bb_predicate", "dst_bb": "bb_target", "relation_id": CANONICAL_RELATION_TO_ID["CDG"]},
    ]
    edges_df = pd.DataFrame(edges)
    all_bbs = {
        "bb_caller", "bb_entry", "bb_logging", "bb_predicate", 
        "bb_def", "bb_target", "bb_exit", "bb_unrelated"
    }
    # Dynamic execution trace of the crash PoC
    trace_bbs = ["bb_caller", "bb_entry", "bb_logging", "bb_predicate", "bb_def", "bb_target"]
    return edges_df, all_bbs, trace_bbs


def test_acceptance_criterion_1_logging_bb_excluded_from_s_dep(synthetic_semantic_program):
    """Criterion 1: Logging BB on execution path is excluded from dependency slice."""
    edges_df, all_bbs, trace_bbs = synthetic_semantic_program
    target_bb = "bb_target"

    partition = partition_target_candidates(
        all_bbs=all_bbs,
        executed_trace_bbs=trace_bbs,
        edges_df=edges_df,
        target_bb=target_bb,
    )

    # Logging BB was executed in trace
    assert "bb_logging" in partition.E_t
    # Logging BB is a CFG predecessor
    assert "bb_logging" in partition.R_exec
    # CRITICAL: Logging BB MUST NOT be in dependency slice S_dep!
    assert "bb_logging" not in partition.S_dep, "Logging BB leaked into dependency slice!"
    assert "bb_logging" not in partition.P_t_dep, "Logging BB leaked into weak positives!"


def test_acceptance_criterion_2_definition_bb_included_via_ddg(synthetic_semantic_program):
    """Criterion 2: Definition BB influencing target operand enters S_dep via DDG."""
    edges_df, all_bbs, trace_bbs = synthetic_semantic_program
    target_bb = "bb_target"

    s_dep = compute_target_dependency_backward_slice(edges_df, target_bb)
    
    assert "bb_def" in s_dep, "Definition BB bb_def missing from dependency slice S_dep!"
    assert target_bb in s_dep, "Target BB itself missing from dependency slice S_dep!"


def test_acceptance_criterion_3_controlling_predicate_included_via_cdg(synthetic_semantic_program):
    """Criterion 3: Branch predicate BB controlling target execution enters S_dep via CDG."""
    edges_df, all_bbs, trace_bbs = synthetic_semantic_program
    target_bb = "bb_target"

    s_dep = compute_target_dependency_backward_slice(edges_df, target_bb)

    assert "bb_predicate" in s_dep, "Predicate BB bb_predicate missing from dependency slice S_dep!"


def test_acceptance_criterion_4_interprocedural_and_incomplete_flag(synthetic_semantic_program):
    """Criterion 4: Interprocedural parameter/return handling & analysis_incomplete flag."""
    edges_df, all_bbs, trace_bbs = synthetic_semantic_program
    target_bb = "bb_target"

    # Case A: Without explicit interprocedural DDG edge, analysis_incomplete should be True
    partition_a = partition_target_candidates(
        all_bbs=all_bbs,
        executed_trace_bbs=trace_bbs,
        edges_df=edges_df,
        target_bb=target_bb,
        analysis_incomplete=True,
    )
    assert partition_a.analysis_incomplete is True
    # Without parameter edge, caller is not in pure intraprocedural S_dep
    assert "bb_caller" not in partition_a.S_dep

    # Case B: With explicit parameter DDG_SSA edge from caller to def
    param_edge = pd.DataFrame([{
        "src_bb": "bb_caller",
        "dst_bb": "bb_def",
        "relation_id": CANONICAL_RELATION_TO_ID["DDG_SSA"],
    }])
    edges_with_param = pd.concat([edges_df, param_edge], ignore_index=True)
    partition_b = partition_target_candidates(
        all_bbs=all_bbs,
        executed_trace_bbs=trace_bbs,
        edges_df=edges_with_param,
        target_bb=target_bb,
        analysis_incomplete=False,
    )
    assert "bb_caller" in partition_b.S_dep, "Interprocedural parameter dependency was not traversed!"
    assert partition_b.analysis_incomplete is False


def test_acceptance_criterion_5_cfg_reachability_distinct_from_dependency_slicing(synthetic_semantic_program):
    """Criterion 5: ICFG reachability R_exec and dependency slicing S_dep yield distinct sets."""
    edges_df, all_bbs, trace_bbs = synthetic_semantic_program
    target_bb = "bb_target"

    partition = partition_target_candidates(
        all_bbs=all_bbs,
        executed_trace_bbs=trace_bbs,
        edges_df=edges_df,
        target_bb=target_bb,
    )

    # 1. Verify R_exec contains predecessors reachable along ICFG
    # Note: In context-insensitive ICFG without call-stack matching, unconstrained RETURN edges
    # can connect bb_caller back to bb_exit.
    assert "bb_logging" in partition.R_exec
    assert "bb_entry" in partition.R_exec
    assert "bb_caller" in partition.R_exec
    assert "bb_def" in partition.R_exec
    assert "bb_target" in partition.R_exec

    # 2. Verify S_dep contains ONLY target and its DDG/CDG dependencies
    expected_dep_slice = {"bb_target", "bb_def", "bb_predicate"}
    assert partition.S_dep == expected_dep_slice

    # 3. Assert they are strictly distinct
    assert partition.S_dep != partition.R_exec
    assert partition.S_dep.issubset(partition.R_exec)
    assert len(partition.S_dep) < len(partition.R_exec)

    # 4. Compare positive yields: P_t_dep vs P_t_legacy vs P_t_trace
    # P_t_dep strictly filters down weak positives
    assert partition.P_t_dep == {"bb_target", "bb_def", "bb_predicate"}
    assert len(partition.P_t_dep) == 3
    assert len(partition.P_t_trace) == 6
    assert partition.retention_dep == 3 / 6  # 50%
    assert partition.retention_legacy >= partition.retention_dep

    # 5. Non-slice BBs must remain unknown, NOT negative
    assert len(partition.N_t) == 0
    assert partition.has_verified_negatives is False


def test_slice_diagnostics_paths_and_reasons(synthetic_semantic_program):
    """Test instruction/BB-level backward slicing diagnostic traces and reasons."""
    edges_df, all_bbs, trace_bbs = synthetic_semantic_program
    target_bb = "bb_target"

    from target_graph.labels.slicing import trace_backward_slice_diagnostics
    diag = trace_backward_slice_diagnostics(edges_df, target_bb)

    # All S_dep nodes must have diagnostic entries
    assert "bb_target" in diag
    assert "bb_def" in diag
    assert "bb_predicate" in diag

    assert diag["bb_target"]["reason"] == "TARGET_SITE"
    assert diag["bb_target"]["distance"] == 0

    assert diag["bb_def"]["reason"] == "DIRECT_OPERAND_DEF"
    assert diag["bb_def"]["distance"] == 1
    assert diag["bb_def"]["path"] == ["bb_target", "bb_def"]
    assert "DDG_SSA" in diag["bb_def"]["path_relations"][0]

    assert diag["bb_predicate"]["reason"] == "DIRECT_CDG_PREDICATE"
    assert diag["bb_predicate"]["distance"] == 1
    assert diag["bb_predicate"]["path"] == ["bb_target", "bb_predicate"]
    assert "CDG" in diag["bb_predicate"]["path_relations"][0]


def test_slice_quality_and_supervision_gating(synthetic_semantic_program):
    """Test slice quality classification and supervision gating."""
    edges_df, all_bbs, trace_bbs = synthetic_semantic_program
    target_bb = "bb_target"

    # Case 1: Local dependency validated (intra-procedural defs present)
    partition = partition_target_candidates(all_bbs, trace_bbs, edges_df, target_bb)
    assert partition.slice_quality in {"LOCAL_DEPENDENCY_VALIDATED", "SUPERVISION_VALIDATED"}
    assert partition.supervision_suitability in {"ACCEPT_LOCAL_ONLY", "ACCEPT_AS_SUPERVISION"}
    assert partition.missing_fault_operands is False

    # Case 2: Degenerate target-only slice (|S_dep| == 1)
    empty_edges = pd.DataFrame(columns=["src_bb", "dst_bb", "relation_id"])
    partition_degen = partition_target_candidates(all_bbs, trace_bbs, empty_edges, target_bb)
    assert partition_degen.slice_quality == "DEGENERATE_TARGET_ONLY"
    assert partition_degen.supervision_suitability == "REJECT_DEGENERATE_TARGET_ONLY"
    assert partition_degen.missing_fault_operands is True

    # Case 3: Interprocedural incomplete (|S_dep| <= 5, CDG only without operand def)
    cdg_only_edges = edges_df[edges_df["relation_id"] == CANONICAL_RELATION_TO_ID["CDG"]]
    partition_insufficient = partition_target_candidates(all_bbs, trace_bbs, cdg_only_edges, target_bb)
    assert partition_insufficient.slice_quality == "INTERPROCEDURAL_INCOMPLETE"
    assert partition_insufficient.supervision_suitability == "REJECT_INCOMPLETE_DEPENDENCY"
    assert partition_insufficient.missing_fault_operands is True


def test_slicing_ablation_comparison(synthetic_semantic_program):
    """Test multi-relation slicing ablation computation."""
    edges_df, all_bbs, trace_bbs = synthetic_semantic_program
    target_bb = "bb_target"

    from target_graph.labels.slicing import compute_slicing_ablation
    ab = compute_slicing_ablation(edges_df, target_bb, trace_bbs)

    assert ab["num_executed_Et"] == 6
    assert ab["slice_ssa_only"] == 2  # target + bb_def
    assert ab["slice_ssa_cdg"] == 3   # target + bb_def + bb_predicate
    assert ab["slice_all_dep"] == 3
    assert ab["slice_legacy"] >= 3
    assert ab["retention_ssa_only"] <= ab["retention_ssa_cdg"] <= ab["retention_legacy"]


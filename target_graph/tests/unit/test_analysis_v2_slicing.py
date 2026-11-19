"""Semantic regressions for instruction-level and callsite-constrained slicing.

All examples are constructed *at the instruction level*, not at the BB level:
the second formal argument must never become relevant simply because the
function has a non-void return value.
"""
from __future__ import annotations

import json
import pytest

from target_graph.analysis_v2.graph import (
    DependencyEdge as Edge,
    DependencyGraph,
    DependencyNode as Node,
)
from target_graph.analysis_v2.slicing import backward_slice


def node(node_id, kind="instruction", bb=None, function="f"):
    return Node(node_id, kind, function, bb or node_id + ":bb", "", 0)


def test_unused_parameter_never_enters_return_value_slice():
    nodes = [
        node("call-A:result", "call_result"), node("use_A"),
        node("ret", function="callee"), node("formal0", "formal", function="callee"),
        node("formal1", "formal", function="callee"),
        node("actual0", function="caller"), node("actual1", function="caller"),
    ]
    edges = [
        Edge("call-A:result", "use_A", "SSA", "verified"),
        Edge("ret", "call-A:result", "RET_BIND", "verified", "call-A"),
        Edge("formal0", "ret", "SSA", "verified", arg_index=0),
        Edge("actual0", "formal0", "PARAM_IN", "verified", "call-A", 0),
        Edge("actual1", "formal1", "PARAM_IN", "verified", "call-A", 1),
    ]
    result = backward_slice(DependencyGraph(nodes, edges), "use_A")
    assert {"use_A", "call-A:result", "ret", "formal0", "actual0"} <= result.nodes
    assert "formal1" not in result.nodes
    assert "actual1" not in result.nodes
    assert result.unknown_boundaries == []
    assert result.validated_for_supervision is False


def test_return_context_blocks_cross_callsite_parameter_mixing():
    nodes = [
        node("resultA", "call_result"), node("resultB", "call_result"),
        node("useA"), node("ret", function="callee"),
        node("formal", "formal", function="callee"),
        node("actualA", function="callerA"), node("actualB", function="callerB"),
    ]
    edges = [
        Edge("resultA", "useA", "SSA", "verified"),
        Edge("ret", "resultA", "RET_BIND", "verified", "callsite-A"),
        Edge("ret", "resultB", "RET_BIND", "verified", "callsite-B"),
        Edge("formal", "ret", "SSA", "verified"),
        Edge("actualA", "formal", "PARAM_IN", "verified", "callsite-A", 0),
        Edge("actualB", "formal", "PARAM_IN", "verified", "callsite-B", 0),
    ]
    result = backward_slice(DependencyGraph(nodes, edges), "useA")
    assert "actualA" in result.nodes
    assert "actualB" not in result.nodes
    assert result.context_rejections >= 1
    # A target *inside* a shared callee may have multiple valid callers.
    unconstrained = backward_slice(DependencyGraph(nodes, edges), "ret")
    assert "actualA" in unconstrained.nodes
    assert "actualB" in unconstrained.nodes


def test_memory_and_indirect_call_boundaries_are_not_claimed_provenance():
    nodes = [node("target"), node("load"), node("unknown_memory", "memory_unknown"),
             node("unknown_call", "unresolved_call")]
    edges = [
        Edge("load", "target", "SSA", "verified"),
        Edge("unknown_memory", "load", "MEMORY_UNKNOWN", "unknown"),
        Edge("unknown_call", "load", "CALL_UNKNOWN", "unknown"),
    ]
    result = backward_slice(DependencyGraph(nodes, edges), "target")
    assert result.nodes == {"target", "load"}
    assert {e["kind"] for e in result.unknown_boundaries} == {
        "MEMORY_UNKNOWN", "CALL_UNKNOWN"
    }
    assert result.validated_for_supervision is False


def test_control_gate_does_not_import_sibling_instructions():
    nodes = [node("branch"), node("gate", "control_gate", "bb_shared"),
             node("target", bb="bb_shared"), node("unrelated", bb="bb_shared")]
    edges = [
        Edge("branch", "gate", "CONTROL", "verified"),
        Edge("gate", "target", "GUARD", "verified"),
        Edge("gate", "unrelated", "GUARD", "verified"),
    ]
    result = backward_slice(DependencyGraph(nodes, edges), "target")
    assert "branch" in result.nodes
    assert "unrelated" not in result.nodes


def test_invalid_edges_and_duplicate_ids_fail_validation():
    with pytest.raises(ValueError, match="Duplicate"):
        DependencyGraph([node("same"), node("same")], [])
    with pytest.raises(ValueError, match="Dangling"):
        DependencyGraph([node("one")], [Edge("missing", "one", "SSA", "verified")])
    with pytest.raises(ValueError, match="callsite_id"):
        DependencyGraph([node("a"), node("b")], [
            Edge("a", "b", "PARAM_IN", "verified", "", 0)
        ])


def test_loader_preserves_identity_and_detects_mixed_artifacts(tmp_path):
    nodes = [node("a"), node("b")]
    edges = [Edge("a", "b", "SSA", "verified")]
    (tmp_path / "analysis_v2_nodes.jsonl").write_text(
        "".join(json.dumps(vars(n)) + "\n" for n in nodes)
    )
    (tmp_path / "analysis_v2_edges.jsonl").write_text(
        "".join(json.dumps(vars(e)) + "\n" for e in edges)
    )
    (tmp_path / "analysis_v2_summary.json").write_text(json.dumps({
        "schema_version": 1, "node_count": 2, "edge_count": 1
    }))
    graph = DependencyGraph.from_directory(tmp_path)
    assert graph.edge_count == 1
    assert "a" in backward_slice(graph, "b").nodes

    (tmp_path / "analysis_v2_summary.json").write_text(json.dumps({
        "schema_version": 1, "node_count": 2, "edge_count": 55
    }))
    with pytest.raises(ValueError, match="mismatch"):
        DependencyGraph.from_directory(tmp_path)


def test_mismatched_legacy_bb_map_is_rejected(tmp_path):
    n = node("only_instruction", bb="v2_bb")
    (tmp_path / "analysis_v2_nodes.jsonl").write_text(
        json.dumps(vars(n)) + "\n"
    )
    (tmp_path / "analysis_v2_edges.jsonl").write_text("")
    (tmp_path / "bb_map.jsonl").write_text(
        json.dumps({"bb_id": "unrelated_legacy_build"}) + "\n"
    )
    with pytest.raises(ValueError, match="ID mismatch"):
        DependencyGraph.from_directory(tmp_path)


def test_call_depth_limit_is_explicitly_reported():
    graph = DependencyGraph(
        [node("target"), node("ret"), node("formal", kind="formal"),
         node("actual")],
        [
            Edge("ret", "target", "RET_BIND", "verified", "call-1"),
            Edge("formal", "ret", "SSA", "verified"),
            Edge("actual", "formal", "PARAM_IN", "verified", "call-1", 0),
        ],
    )
    # A depth of one still supports a single balanced interprocedural call.
    result = backward_slice(graph, "target", max_call_depth=1)
    assert "actual" in result.nodes
    assert not result.truncated


def test_inlined_source_location_search_returns_all_llvm_owners():
    """The out-of-line callee cannot be selected just by file:line."""
    graph = DependencyGraph(
        [
            Node("out:0", "instruction", "parseSWF_RGBA", "bb_out",
                 "store", 68, "/build/util/parser.c"),
            Node("inl1:7", "instruction", "parseSWF_MORPHGRADIENTRECORD",
                 "bb_inl1", "store", 68, "/build/util/parser.c"),
            Node("inl2:2", "instruction", "parseSWF_MORPHFILLSTYLE",
                 "bb_inl2", "store", 68, "/build/util/parser.c"),
            Node("other:0", "instruction", "unrelated", "bb_other",
                 "store", 68, "/build/util/other.c"),
        ],
        [],
    )
    matches = graph.candidate_fault_instructions_by_source(
        "parser.c", 68, "store"
    )
    assert len(matches) == 3
    assert {n.function for n in matches} == {
        "parseSWF_RGBA", "parseSWF_MORPHGRADIENTRECORD",
        "parseSWF_MORPHFILLSTYLE",
    }
    assert len(graph.candidate_fault_instructions_by_source(
        "/build/util/parser.c", 68, "store"
    )) == 3


def test_formal_without_actual_binding_is_explicit_unknown_boundary():
    """A source-level inlined function may retain an uncalled definition."""
    formal = "build:parseSWF_RGBA:formal:1"
    graph = DependencyGraph(
        [
            node("fault", bb="fault_bb", function="parseSWF_RGBA"),
            node(formal, "formal", "entry_bb", "parseSWF_RGBA"),
        ],
        [Edge(formal, "fault", "SSA", "verified", arg_index=1)],
    )
    result = backward_slice(graph, "fault")
    assert formal in result.unbound_formals
    assert any(
        boundary["kind"] == "UNBOUND_FORMAL"
        and boundary["src"] == formal
        for boundary in result.unknown_boundaries
    )
    assert result.validated_for_supervision is False

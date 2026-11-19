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

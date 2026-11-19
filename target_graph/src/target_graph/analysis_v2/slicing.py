"""Callsite-constrained backward value-flow traversal.

NOT a general-purpose context-sensitive SDG: this is a balanced-call
under-approximation over *exported* SSA, PARAM_IN and RET_BIND relations.
When the analysis starts inside a callee with no known caller context, all
direct callers are possible; only a matched nested RET_BIND constrains which
PARAM_IN may return to the caller. Unknown memory and indirect calls stop
the traversal and are recorded as unresolved boundaries.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from .graph import DependencyEdge, DependencyGraph

TRAVERSABLE_RELATIONS = frozenset({
    "SSA", "VALUE_REFERENCE", "GUARD", "CONTROL", "PARAM_IN", "RET_BIND"
})
State = Tuple[str, Tuple[str, ...]]  # (node_id, stack of pending callsites)


@dataclass
class SliceResult:
    target: str
    nodes: Set[str] = field(default_factory=set)
    basic_blocks: Set[str] = field(default_factory=set)
    unknown_boundaries: List[Dict[str, str]] = field(default_factory=list)
    unbound_formals: List[str] = field(default_factory=list)
    context_rejections: int = 0
    truncated: bool = False
    truncation_reasons: List[str] = field(default_factory=list)
    states_visited: int = 0
    # A single representative proof path per node, not an exhaustive proof.
    paths: Dict[str, List[str]] = field(default_factory=dict)
    path_evidence: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)

    @property
    def validated_for_supervision(self) -> bool:
        # No instruction-level path through the current approximate analysis
        # suffices to validate vulnerability-triggering supervision.
        return False

    def as_dict(self, max_paths: int = 100) -> dict:
        return {
            "schema_version": 1,
            "target": self.target,
            "node_count": len(self.nodes),
            "basic_block_count": len(self.basic_blocks),
            "basic_blocks": sorted(self.basic_blocks),
            "unknown_boundaries": self.unknown_boundaries,
            "unbound_formals": self.unbound_formals,
            "context_rejections": self.context_rejections,
            "truncated": self.truncated,
            "truncation_reasons": self.truncation_reasons,
            "states_visited": self.states_visited,
            "validated_for_supervision": False,
            "representative_paths": dict(list(sorted(self.paths.items()))[:max_paths]),
            "representative_edge_evidence": dict(list(sorted(self.path_evidence.items()))[:max_paths]),
        }


def backward_slice(
    graph: DependencyGraph,
    target_instruction: str,
    *,
    max_call_depth: int = 8,
    max_states: int = 200_000,
) -> SliceResult:
    if target_instruction not in graph.nodes:
        raise KeyError(f"Unknown target instruction: {target_instruction}")
    if max_call_depth < 1 or max_states < 1:
        raise ValueError("max_call_depth and max_states must both be >= 1")

    result = SliceResult(target=target_instruction)
    root: State = (target_instruction, ())
    queue = deque([root])
    parents: Dict[State, State | None] = {root: None}
    witness_edges: Dict[State, DependencyEdge] = {}
    first_seen_node: Dict[str, State] = {target_instruction: root}
    boundary_keys: Set[Tuple[str, str, str, str]] = set()

    while queue:
        if len(parents) > max_states:
            result.truncated = True
            result.truncation_reasons.append("max_states")
            break
        node_id, stack = queue.popleft()
        result.nodes.add(node_id)
        bb_id = graph.nodes[node_id].bb_id
        if bb_id:
            result.basic_blocks.add(bb_id)

        # An LLVM formal value is not a proof of its caller-supplied source.
        # This may mean inlining, indirect/external callers, or a root entry
        # point. Make this missing binding explicit rather than silently
        # terminating a seemingly complete fault-operand chain.
        if graph.nodes[node_id].kind == "formal" and not any(
            edge.kind == "PARAM_IN" for edge in graph.incoming.get(node_id, ())
        ) and node_id not in result.unbound_formals:
            result.unbound_formals.append(node_id)
            key = ("UNBOUND_FORMAL", node_id, node_id, "unknown")
            if key not in boundary_keys:
                boundary_keys.add(key)
                result.unknown_boundaries.append({
                    "kind": "UNBOUND_FORMAL", "src": node_id,
                    "dst": node_id, "status": "unknown",
                })

        for edge in graph.incoming.get(node_id, ()):
            if edge.status != "verified" or edge.kind not in TRAVERSABLE_RELATIONS:
                key = (edge.kind, edge.src, edge.dst, edge.status)
                if key not in boundary_keys:
                    boundary_keys.add(key)
                    result.unknown_boundaries.append({
                        "kind": edge.kind, "src": edge.src,
                        "dst": edge.dst, "status": edge.status,
                    })
                continue

            new_stack = stack
            if edge.kind == "RET_BIND":
                if len(stack) >= max_call_depth:
                    result.truncated = True
                    if "max_call_depth" not in result.truncation_reasons:
                        result.truncation_reasons.append("max_call_depth")
                    continue
                new_stack = stack + (edge.callsite_id,)
            elif edge.kind == "PARAM_IN" and stack:
                if stack[-1] != edge.callsite_id:
                    result.context_rejections += 1
                    continue
                new_stack = stack[:-1]

            predecessor = (edge.src, new_stack)
            if predecessor in parents:
                continue
            parents[predecessor] = (node_id, stack)
            witness_edges[predecessor] = edge
            first_seen_node.setdefault(edge.src, predecessor)
            queue.append(predecessor)

    result.states_visited = len(parents)
    # One witness per visited instruction. Retain the actual reverse edge
    # traversal from target to dependency source.
    for node, state in first_seen_node.items():
        if node not in result.nodes:
            continue
        path = []
        evidence = []
        current: State | None = state
        while current is not None:
            path.append(current[0])
            if current in witness_edges:
                edge = witness_edges[current]
                evidence.append({
                    "src": edge.src, "dst": edge.dst,
                    "kind": edge.kind, "status": edge.status,
                    "callsite_id": edge.callsite_id,
                    "arg_index": str(edge.arg_index),
                })
            current = parents[current]
        result.paths[node] = list(reversed(path))
        result.path_evidence[node] = list(reversed(evidence))
    return result

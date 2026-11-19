"""Validated loading for LLVM analysis-v2 instruction and dependency records."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
from typing import DefaultDict, Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class DependencyNode:
    id: str
    kind: str
    function: str
    bb_id: str
    text: str
    line: int = 0
    source_file: str = ""
    called_function: str = ""


@dataclass(frozen=True)
class DependencyEdge:
    src: str
    dst: str
    kind: str
    status: str
    callsite_id: str = ""
    arg_index: int = -1


class DependencyGraph:
    """Do not silently merge duplicate node IDs or trust dangling relations."""

    def __init__(self, nodes: Iterable[DependencyNode], edges: Iterable[DependencyEdge]):
        self.nodes: Dict[str, DependencyNode] = {}
        self.incoming: DefaultDict[str, List[DependencyEdge]] = defaultdict(list)
        self.edge_count = 0
        for node in nodes:
            if not node.id or node.id in self.nodes:
                raise ValueError(f"Duplicate or empty instruction node ID: {node.id!r}")
            self.nodes[node.id] = node
        for edge in edges:
            if edge.src not in self.nodes or edge.dst not in self.nodes:
                raise ValueError(
                    f"Dangling dependency edge: {edge.src!r} -> {edge.dst!r} ({edge.kind})"
                )
            if edge.kind in {"PARAM_IN", "RET_BIND"} and not edge.callsite_id:
                raise ValueError(f"Interprocedural edge lacks callsite_id: {edge!r}")
            if edge.kind == "PARAM_IN" and edge.arg_index < 0:
                raise ValueError(f"PARAM_IN edge lacks argument index: {edge!r}")
            self.incoming[edge.dst].append(edge)
            self.edge_count += 1

    @staticmethod
    def _load_lines(path: Path):
        with path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{line_number}: malformed JSON") from exc
                if not isinstance(obj, dict):
                    raise ValueError(f"{path}:{line_number}: expected JSON object")
                yield obj

    @classmethod
    def from_directory(cls, directory: str | Path) -> "DependencyGraph":
        directory = Path(directory)
        nodes_file = directory / "analysis_v2_nodes.jsonl"
        edges_file = directory / "analysis_v2_edges.jsonl"
        nodes = [
            DependencyNode(
                id=str(row["id"]),
                kind=str(row["kind"]),
                function=str(row["function"]),
                bb_id=str(row["bb_id"]),
                text=str(row.get("text", "")),
                line=int(row.get("line", 0)),
                source_file=str(row.get("source_file", "")),
                called_function=str(row.get("called_function", "")),
            )
            for row in cls._load_lines(nodes_file)
        ]
        edges = [
            DependencyEdge(
                src=str(row["src"]),
                dst=str(row["dst"]),
                kind=str(row["kind"]),
                status=str(row.get("status", "unknown")),
                callsite_id=str(row.get("callsite_id", "")),
                arg_index=int(row.get("arg_index", -1)),
            )
            for row in cls._load_lines(edges_file)
        ]
        graph = cls(nodes, edges)
        summary_path = directory / "analysis_v2_summary.json"
        if summary_path.exists():
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            if summary.get("schema_version") != 1:
                raise ValueError("Unsupported analysis-v2 summary schema")
            if summary.get("node_count") != len(graph.nodes):
                raise ValueError("Node count mismatch; mixed/stale analysis artifacts")
            if summary.get("edge_count") != graph.edge_count:
                raise ValueError("Edge count mismatch; mixed/stale analysis artifacts")
        # Refuse to silently align a v2 graph with a legacy graph from
        # another bitcode build. Matching BB IDs are essential for traces.
        bb_map = directory / "bb_map.jsonl"
        if bb_map.exists():
            legacy_ids = {
                str(item["bb_id"]) for item in cls._load_lines(bb_map)
            }
            v2_ids = {
                node.bb_id for node in graph.nodes.values()
                if node.kind == "instruction"
            }
            if v2_ids != legacy_ids:
                raise ValueError(
                    "V2/legacy basic-block ID mismatch: regenerate both "
                    "graphs from the same bitcode and build_id"
                )
        return graph

    def candidate_fault_instructions(
        self,
        bb_id: str,
        line: Optional[int] = None,
        opcode: Optional[str] = None,
    ) -> List[DependencyNode]:
        return sorted(
            [
                node for node in self.nodes.values()
                if node.kind == "instruction"
                and node.bb_id == bb_id
                and (line is None or node.line == line)
                and (opcode is None or node.text == opcode)
            ],
            key=lambda node: node.id,
        )

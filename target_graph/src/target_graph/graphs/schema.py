"""Graph schema definitions, Pydantic validation models, and Parquet table specs."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import pyarrow as pa
import pyarrow.parquet as pq
from pydantic import BaseModel, Field

SCHEMA_VERSION = "3.0.0"

# --- PyArrow Schemas ---

NODES_ARROW_SCHEMA = pa.schema([
    ("build_id", pa.string()),
    ("bb_id", pa.string()),
    ("function_id", pa.string()),
    ("source_spans", pa.string()),        # JSON list of {file, start_line, start_col, end_line, end_col}
    ("instruction_ids", pa.string()),    # JSON list of instruction IDs
    ("mapping_status", pa.string()),     # mapped, synthetic, ambiguous, macro
    ("is_entry", pa.bool_()),
    ("is_exit", pa.bool_()),
])

EDGES_ARROW_SCHEMA = pa.schema([
    ("src_bb", pa.string()),
    ("dst_bb", pa.string()),
    ("relation_id", pa.int32()),
    ("callsite_id", pa.string()),        # Unambiguous callsite identifier or empty
    ("evidence_count", pa.int32()),
    ("analysis_status", pa.string()),    # verified, may, must, approximate
    ("evidence_ref", pa.string()),
])

EDGE_EVIDENCE_ARROW_SCHEMA = pa.schema([
    ("evidence_ref", pa.string()),
    ("src_inst", pa.string()),
    ("dst_inst", pa.string()),
    ("analysis_tool", pa.string()),
    ("dependence_kind", pa.string()),    # ssa, may_mem, must_mem, cdg_predicate, etc.
    ("source_location", pa.string()),
])

FUNCTIONS_ARROW_SCHEMA = pa.schema([
    ("function_id", pa.string()),
    ("entry_bb", pa.string()),
    ("exit_bbs", pa.string()),           # JSON list of exit BB IDs
    ("callsites", pa.string()),          # JSON list of callsite IDs
    ("source_hash", pa.string()),
])

LABELS_ARROW_SCHEMA = pa.schema([
    ("case_id", pa.string()),
    ("build_id", pa.string()),
    ("target_bb", pa.string()),
    ("candidate_bb", pa.string()),
    ("label", pa.string()),              # positive, negative, unknown
    ("evidence_kind", pa.string()),      # dynamic_executed_slice, unexecuted_slice, executed_nonslice, verified_negative
    ("slice_version", pa.string()),
    ("trace_run_ids", pa.string()),      # JSON list of trace run IDs
    ("quality_tier", pa.string()),       # weak_positive, strong_positive, qualified_negative, unknown
])


# --- Pydantic Data Models ---

class SourceSpan(BaseModel):
    file: str
    start_line: int
    start_col: int = 0
    end_line: int
    end_col: int = 0


class NodeRecord(BaseModel):
    build_id: str
    bb_id: str
    function_id: str
    source_spans: List[SourceSpan] = Field(default_factory=list)
    instruction_ids: List[str] = Field(default_factory=list)
    mapping_status: str = "mapped"  # mapped, synthetic, ambiguous, macro
    is_entry: bool = False
    is_exit: bool = False

    def to_arrow_row(self) -> Dict[str, Any]:
        return {
            "build_id": self.build_id,
            "bb_id": self.bb_id,
            "function_id": self.function_id,
            "source_spans": json.dumps([s.model_dump() for s in self.source_spans]),
            "instruction_ids": json.dumps(self.instruction_ids),
            "mapping_status": self.mapping_status,
            "is_entry": self.is_entry,
            "is_exit": self.is_exit,
        }


class EdgeRecord(BaseModel):
    src_bb: str
    dst_bb: str
    relation_id: int
    callsite_id: str = ""
    evidence_count: int = 1
    analysis_status: str = "verified"
    evidence_ref: str = ""

    def to_arrow_row(self) -> Dict[str, Any]:
        return {
            "src_bb": self.src_bb,
            "dst_bb": self.dst_bb,
            "relation_id": self.relation_id,
            "callsite_id": self.callsite_id,
            "evidence_count": self.evidence_count,
            "analysis_status": self.analysis_status,
            "evidence_ref": self.evidence_ref,
        }


class EdgeEvidenceRecord(BaseModel):
    evidence_ref: str
    src_inst: str = ""
    dst_inst: str = ""
    analysis_tool: str = "llvm"
    dependence_kind: str = "ssa"
    source_location: str = ""

    def to_arrow_row(self) -> Dict[str, Any]:
        return {
            "evidence_ref": self.evidence_ref,
            "src_inst": self.src_inst,
            "dst_inst": self.dst_inst,
            "analysis_tool": self.analysis_tool,
            "dependence_kind": self.dependence_kind,
            "source_location": self.source_location,
        }


class FunctionRecord(BaseModel):
    function_id: str
    entry_bb: str
    exit_bbs: List[str] = Field(default_factory=list)
    callsites: List[str] = Field(default_factory=list)
    source_hash: str = ""

    def to_arrow_row(self) -> Dict[str, Any]:
        return {
            "function_id": self.function_id,
            "entry_bb": self.entry_bb,
            "exit_bbs": json.dumps(self.exit_bbs),
            "callsites": json.dumps(self.callsites),
            "source_hash": self.source_hash,
        }


class GraphMetadata(BaseModel):
    schema_version: str = SCHEMA_VERSION
    build_id: str
    ir_hash: str
    llvm_version: str
    svf_version: str = "none"
    coverage: Dict[str, Any] = Field(default_factory=dict)
    unresolved_calls: int = 0
    node_count: int = 0
    edge_count: int = 0


class LabelRecord(BaseModel):
    case_id: str
    build_id: str
    target_bb: str
    candidate_bb: str
    label: str  # positive, negative, unknown
    evidence_kind: str  # dynamic_executed_slice, unexecuted_slice, executed_nonslice, verified_negative
    slice_version: str = "1.0"
    trace_run_ids: List[str] = Field(default_factory=list)
    quality_tier: str = "weak_positive"

    def to_arrow_row(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "build_id": self.build_id,
            "target_bb": self.target_bb,
            "candidate_bb": self.candidate_bb,
            "label": self.label,
            "evidence_kind": self.evidence_kind,
            "slice_version": self.slice_version,
            "trace_run_ids": json.dumps(self.trace_run_ids),
            "quality_tier": self.quality_tier,
        }


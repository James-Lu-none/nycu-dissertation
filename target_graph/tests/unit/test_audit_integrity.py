"""Regression tests for fail-closed label audits and evidence integrity."""
import csv
import json

import pandas as pd

from target_graph.labels.slicing import partition_target_candidates
from target_graph.pipelines.label_audit import (
    generate_provenance_audit,
    generate_toolchain_comparison,
)


def test_incoming_bb_ddg_does_not_prove_all_fault_operands():
    edges = pd.DataFrame([
        {"src_bb": "definition", "dst_bb": "target", "relation_id": 4,
         "analysis_status": "verified"},
        {"src_bb": "entry", "dst_bb": "definition", "relation_id": 2,
         "analysis_status": "verified"},
    ])
    result = partition_target_candidates(
        all_bbs={"entry", "definition", "target"},
        executed_trace_bbs={"entry", "definition", "target"},
        edges_df=edges,
        target_bb="target",
    )
    assert result.S_dep == {"definition", "target"}
    assert result.fault_operand_coverage is None
    assert result.analysis_incomplete is True
    assert result.supervision_suitability == "REJECT_UNVERIFIED_PROVENANCE"


def test_audit_reports_never_invent_provenance_or_tool_measurements(tmp_path):
    class Record:
        case_id = "case-a"
        target_bb = "target"
        supervision_suitability = "REJECT_UNVERIFIED_PROVENANCE"

    path = generate_provenance_audit([Record()], tmp_path)
    data = json.loads(path.read_text())
    assert data["verification_status"] == "NOT_VERIFIED"
    assert data["cases"]["case-a"]["verified_operand_paths"] == []
    assert data["cases"]["case-a"]["fault_operand_coverage"] is None

    csv_path = generate_toolchain_comparison(tmp_path)
    with csv_path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows == []
    status = json.loads((tmp_path / "toolchain_comparison.status.json").read_text())
    assert status["verification_status"] == "NOT_MEASURED"

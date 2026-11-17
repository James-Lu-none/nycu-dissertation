"""Integration test for 5-case Label-Yield Audit pipeline."""
from pathlib import Path
import json
import pytest

from target_graph.pipelines.label_audit import run_full_label_audit


def test_five_case_label_yield_audit(tmp_path):
    config_path = Path("/home/user/workspace/nycu-dissertation/target_graph/configs/projects/cases.yaml")
    cases_root = Path("/home/user/workspace/nycu-dissertation/target_graph/cases")
    output_dir = tmp_path / "reports"

    records = run_full_label_audit(config_path, cases_root, output_dir)

    assert len(records) >= 5, f"Expected at least 5 cases, got {len(records)}"

    for r in records:
        assert r.oracle_reproduced is True, f"Case {r.case_id} failed oracle reproduction"
        assert r.fault_bb_in_trace is True, f"Case {r.case_id} fault BB not in trace"
        assert r.num_nodes_V > 500, f"Case {r.case_id} has insufficient nodes: {r.num_nodes_V}"
        assert r.num_edges > 1000, f"Case {r.case_id} has insufficient edges: {r.num_edges}"
        assert r.num_executed_Et > 0, f"Case {r.case_id} has empty trace"
        assert r.num_slice_St > 0, f"Case {r.case_id} has empty backward slice"
        assert r.num_reachability_Rt > 0, f"Case {r.case_id} has empty reachability"
        assert r.positive_yield > 0, f"Case {r.case_id} has empty positive yield"
        assert 0.0 < r.trace_coverage <= 1.0
        assert 0.0 < r.slice_coverage <= 1.0
        assert r.num_verified_negatives_Nt == 0, f"Case {r.case_id} should have 0 verified negatives"
        assert r.has_verified_negatives is False
        assert r.training_recommendation == "skip_pairwise_ranking_use_pu_learning"
        assert r.target_bb != ""

    # Check generated files
    json_file = output_dir / "label_yield_audit.json"
    csv_file = output_dir / "label_yield_audit.csv"
    md_file = output_dir / "label_yield_audit.md"

    assert json_file.exists() and json_file.stat().st_size > 0
    assert csv_file.exists() and csv_file.stat().st_size > 0
    assert md_file.exists() and md_file.stat().st_size > 0

    with open(json_file) as f:
        data = json.load(f)
    assert len(data) >= 5


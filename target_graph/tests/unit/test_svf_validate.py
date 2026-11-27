"""SVF value-flow evidence is deliberately exploratory and fail-closed."""
from __future__ import annotations

import copy
import json

import pytest

from target_graph.svf.validate import preflight, validate_svf
from target_graph.svf.provenance import canonical_identity


@pytest.fixture()
def example(tmp_path):
    before = tmp_path / "before.jsonl"
    before.write_text(
        "\n".join(json.dumps(row) for row in [
            {"id": "bb0:0", "bb_id": "bb0", "opcode": "load", "function": "main"},
            {"id": "bb1:0", "bb_id": "bb1", "opcode": "store", "function": "main"},
            {"id": "bb1:1", "bb_id": "bb1", "opcode": "ret", "function": "main"},
        ]) + "\n",
        encoding="utf-8",
    )
    bb_map = tmp_path / "bb_map.jsonl"
    bb_map.write_text('{"bb_id":"bb0"}\n{"bb_id":"bb1"}\n')
    v2 = tmp_path / "analysis_v2_nodes.jsonl"
    v2.write_text(
        "".join(json.dumps({"id": inst, "kind": "instruction"}) + "\n"
                for inst in ("bb0:0", "bb1:0", "bb1:1"))
    )
    bc = tmp_path / "source.bc"
    bc.write_bytes(b"fixed same bitcode")
    raw = {
        "schema_version": 1,
        "backend": "SVF-2.9/SVFG",
        "analysis": "BACKWARD_VALUE_FLOW_ONLY",
        "status": "EXPLORATORY_ONLY",
        "validated_for_supervision": False,
        "target_site_verified": False,
        "context_sensitive": False,
        "control_dependencies_included": False,
        "target": "bb1:0",
        "target_seed_svfg_ids": [2],
        "svfg_total_nodes": 9,
        "visited_svfg_nodes": 3,
        "mapped_svfg_nodes": 2,
        "unmapped_svfg_nodes": 1,
        "traversed_edges": 2,
        "instruction_ids": ["bb0:0", "bb1:0"],
        "basic_blocks": ["bb0", "bb1"],
        "svfg_nodes": [
            {"svfg_id": 2, "svfg_kind": 2, "instruction_id": "bb1:0", "bb_id": "bb1"},
            {"svfg_id": 4, "svfg_kind": 9, "instruction_id": None, "bb_id": None},
            {"svfg_id": 5, "svfg_kind": 2, "instruction_id": "bb0:0", "bb_id": "bb0"},
        ],
        "svfg_edges": [
            {"src_svfg_id": 4, "dst_svfg_id": 2,
             "kind": "INTRA_INDIRECT_VALUE_FLOW", "analysis_status": "may"},
            {"src_svfg_id": 5, "dst_svfg_id": 4,
             "kind": "CALL_DIRECT_VALUE_FLOW", "analysis_status": "may"},
        ],
    }
    output = tmp_path / "raw.json"
    output.write_text(json.dumps(raw), encoding="utf-8")
    return before, output, bc, bb_map, v2, raw


def validate(example, raw_override=None):
    before, output, bc, bb_map, v2, raw = example
    if raw_override is not None:
        output.write_text(json.dumps(raw_override), encoding="utf-8")
    return validate_svf(
        before, output, "bb1:0", bc, bb_map=bb_map, v2_nodes=v2
    )


def test_preflight_rejects_stale_target_before_expensive_analysis(example):
    before, _, _, bb_map, v2, _ = example
    with pytest.raises(ValueError, match="was not tagged"):
        preflight(before, "stale:999", bb_map=bb_map, v2_nodes=v2)
    assert len(preflight(before, "bb1:0", bb_map=bb_map, v2_nodes=v2)) == 3


def test_native_svfg_value_flow_is_exploratory_not_cdg(example):
    result = validate(example)
    assert result["basic_blocks"] == ["bb0", "bb1"]
    assert result["visited_svfg_nodes"] == 3
    assert result["unmapped_svfg_nodes"] == 1
    assert result["validated_for_supervision"] is False
    assert result["control_dependencies_included"] is False
    assert result["context_sensitive"] is False
    assert len(result["original_bitcode_sha256"]) == 64


@pytest.mark.parametrize("update,match", [
    ({"target_site_verified": True}, "overclaims"),
    ({"context_sensitive": True}, "overclaims"),
    ({"control_dependencies_included": True}, "overclaims"),
    ({"target": "other:0"}, "target instruction mismatch"),
    ({"target_seed_svfg_ids": [5]}, "Target seeds"),
    ({"instruction_ids": ["bb1:0"]}, "instruction list"),
    ({"basic_blocks": ["bb1"]}, "BB list"),
    ({"visited_svfg_nodes": 4}, "traversal counts"),
])
def test_rejects_invalid_output_metadata(example, update, match):
    raw = copy.deepcopy(example[-1])
    raw.update(update)
    with pytest.raises(ValueError, match=match):
        validate(example, raw)


def test_rejects_unknown_instruction_or_forged_edge(example):
    raw = copy.deepcopy(example[-1])
    raw["svfg_nodes"][2]["instruction_id"] = "unknown:0"
    with pytest.raises(ValueError, match="Unrecognized LLVM instruction"):
        validate(example, raw)
    raw = copy.deepcopy(example[-1])
    raw["svfg_edges"][0]["src_svfg_id"] = 777
    with pytest.raises(ValueError, match="Dangling SVFG"):
        validate(example, raw)
    raw = copy.deepcopy(example[-1])
    raw["svfg_edges"][0]["analysis_status"] = "verified"
    with pytest.raises(ValueError, match="overconfident"):
        validate(example, raw)


def test_rejects_build_id_mismatch_and_unverified_targets(example):
    before, _, _, bb_map, v2, _ = example
    v2.write_text('{"id":"wrong","kind":"instruction"}\n')
    with pytest.raises(ValueError, match="differ"):
        preflight(before, "bb1:0", bb_map=bb_map, v2_nodes=v2)
    v2.write_text(
        "".join(json.dumps({"id": inst, "kind": "instruction"}) + "\n"
                for inst in ("bb0:0", "bb1:0", "bb1:1"))
    )
    bb_map.write_text('{"bb_id":"bb0"}\n')
    with pytest.raises(ValueError, match="not present in bb_map"):
        preflight(before, "bb1:0", bb_map=bb_map, v2_nodes=v2)



def test_canonical_provenance_not_aliased_case_id(tmp_path):
    summary = tmp_path / "pass_summary.json"
    summary.write_text(json.dumps({
        "build_id": "imageworsener-1.3.1_imagew_CVE-2017-9204",
        "module_name": "/workspace/cases/"
                       "imageworsener-1.3.1_imagew_CVE-2017-9204/imagew.bc",
    }))
    assert canonical_identity(summary, "imagew.bc") == (
        "imageworsener-1.3.1_imagew_CVE-2017-9204",
        "/workspace/cases/"
        "imageworsener-1.3.1_imagew_CVE-2017-9204/imagew.bc",
    )
    with pytest.raises(ValueError, match="Bitcode file name differs"):
        canonical_identity(summary, "different.bc")


def test_provenance_missing_or_incomplete_is_not_guessed(tmp_path):
    summary = tmp_path / "pass_summary.json"
    with pytest.raises(ValueError, match="Missing"):
        canonical_identity(summary, "x.bc")
    summary.write_text('{"build_id": "alias", "module_name": ""}')
    with pytest.raises(ValueError, match="invalid canonical"):
        canonical_identity(summary, "x.bc")


def test_mismatched_alias_is_detected_before_target(example):
    before, _, _, bb_map, v2, _ = example
    # Same underlying LLVM structure but different build/module hash.
    before.write_text(
        '{"id":"alias0:0","bb_id":"alias0","function":"main","opcode":"load"}\n'
        '{"id":"alias1:0","bb_id":"alias1","function":"main","opcode":"store"}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Original identities not present in bb_map"):
        preflight(before, "alias1:0", bb_map=bb_map, v2_nodes=v2)


def test_matching_id_but_wrong_opcode_is_not_accepted(example):
    before, _, _, bb_map, v2, _ = example
    rows = [
        {"kind":"instruction", "id":"bb0:0", "function":"main", "text":"sub"},
        {"kind":"instruction", "id":"bb1:0", "function":"main", "text":"store"},
        {"kind":"instruction", "id":"bb1:1", "function":"main", "text":"ret"},
    ]
    v2.write_text("".join(json.dumps(row) + "\n" for row in rows))
    with pytest.raises(ValueError, match="function/opcode mismatch"):
        preflight(before, "bb1:0", bb_map=bb_map, v2_nodes=v2)



def test_multi_candidate_resolves_single_target_and_checks_seeds(example):
    before, output, bc, bb_map, v2, raw = example
    requested = "bb0:0,bb1:0,bb1:1"
    result = validate_svf(before, output, requested, bc,
                          bb_map=bb_map, v2_nodes=v2)
    assert result["target"] == "bb1:0"
    assert result["requested_target_candidates"] == requested.split(",")
    tampered = copy.deepcopy(raw)
    tampered["target_seed_svfg_ids"] = [5]  # other candidate, not resolved target
    output.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="Target seeds"):
        validate_svf(before, output, requested, bc,
                     bb_map=bb_map, v2_nodes=v2)

"""No LLVM installation required: fail-closed DG identity checks."""
from __future__ import annotations

import json

import pytest

from target_graph.dg.validate import validate_survivors
from target_graph.dg.compare import compare


def write_rows(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


@pytest.fixture
def sample(tmp_path):
    before = write_rows(tmp_path / "before.jsonl", [
        {"id": "bb0:0", "bb_id": "bb0", "function": "main", "opcode": "add"},
        {"id": "bb0:1", "bb_id": "bb0", "function": "main", "opcode": "br"},
        {"id": "bb1:0", "bb_id": "bb1", "function": "main", "opcode": "call"},
    ])
    after = write_rows(tmp_path / "after.jsonl", [
        {"id": "bb0:0", "bb_id": "bb0", "function": "main", "opcode": "add"},
        {"id": "bb1:0", "bb_id": "bb1", "function": "main", "opcode": "call"},
    ])
    bbs = write_rows(tmp_path / "bb_map.jsonl", [
        {"bb_id": "bb0"}, {"bb_id": "bb1"}
    ])
    v2 = write_rows(tmp_path / "analysis_v2_nodes.jsonl", [
        {"id": "bb0:0", "kind": "instruction"},
        {"id": "bb0:1", "kind": "instruction"},
        {"id": "bb1:0", "kind": "instruction"},
        {"id": "bb1:control_gate", "kind": "control_gate"},
    ])
    bc = tmp_path / "input.bc"
    bc.write_bytes(b"bitcode-fixture")
    return before, after, bbs, v2, bc


def validate(sample, *, target="bb1:0", criterion="sink"):
    before, after, bbs, v2, bc = sample
    return validate_survivors(
        before, after, target, bb_map=bbs, v2_nodes=v2,
        criterion=criterion, source_bc=bc
    )


def test_preserves_original_instruction_ids_and_no_training_claim(sample):
    payload = validate(sample)
    assert payload["basic_blocks"] == ["bb0", "bb1"]
    assert payload["removed_instruction_count"] == 1
    assert payload["validated_for_supervision"] is False
    assert payload["criterion_verified"] is False
    assert len(payload["original_bitcode_sha256"]) == 64


def test_target_must_be_present_before_and_after(sample):
    with pytest.raises(ValueError, match="did not retain"):
        validate(sample, target="bb0:1")
    with pytest.raises(ValueError, match="was not tagged"):
        validate(sample, target="missing:0")


def test_rejects_new_id_and_duplicate_id(sample):
    _, after, _, _, _ = sample
    with after.open("a", encoding="utf-8") as out:
        out.write('{"id":"bb2:0","bb_id":"bb2"}\n')
    with pytest.raises(ValueError, match="unknown original"):
        validate(sample)
    write_rows(after, [
        {"id": "bb1:0", "bb_id": "bb1"},
        {"id": "bb1:0", "bb_id": "bb1"},
    ])
    with pytest.raises(ValueError, match="duplicate"):
        validate(sample)


def test_rejects_mismatched_legacy_and_v2_builds(sample):
    _, _, bbs, v2, _ = sample
    write_rows(bbs, [{"bb_id": "other"}])
    with pytest.raises(ValueError, match="does not match bb_map"):
        validate(sample)
    write_rows(bbs, [{"bb_id": "bb0"}, {"bb_id": "bb1"}])
    write_rows(v2, [{"kind": "instruction", "id": "wrong:0"}])
    with pytest.raises(ValueError, match="do not match analysis_v2"):
        validate(sample)


def test_rejects_invalid_criterion_or_missing_metadata(sample):
    with pytest.raises(ValueError, match="Explicit DG criterion"):
        validate(sample, criterion="")
    before = sample[0]
    write_rows(before, [{"id": "bb0:0", "bb_id": "not-bb0"}])
    with pytest.raises(ValueError, match="inconsistent BB"):
        validate(sample)


def test_compare_requires_same_target_and_marks_unvalidated(tmp_path):
    write_rows(tmp_path / "analysis_v2_nodes.jsonl", [
        {"id": "bb0:0", "kind": "instruction", "function": "f",
         "bb_id": "bb0", "text": "add"},
        {"id": "bb1:0", "kind": "instruction", "function": "f",
         "bb_id": "bb1", "text": "store"},
    ])
    write_rows(tmp_path / "analysis_v2_edges.jsonl", [
        {"src": "bb0:0", "dst": "bb1:0", "kind": "SSA",
         "status": "verified"}
    ])
    report = tmp_path / "dg_slice.json"
    report.write_text(json.dumps({
        "backend": "DG/llvm-slicer",
        "target": "bb1:0", "basic_blocks": ["bb1"],
        "validated_for_supervision": False,
    }), encoding="utf-8")
    comparison = compare(tmp_path, report, "bb1:0")
    assert comparison["v2_only_bbs"] == ["bb0"]
    assert comparison["dg_bbs"] == 1
    assert comparison["validated_for_supervision"] is False
    with pytest.raises(ValueError, match="target instruction mismatch"):
        compare(tmp_path, report, "bb0:0")

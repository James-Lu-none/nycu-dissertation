"""BB DebugLoc union must not promote unrelated LLVM instructions."""
import json

from target_graph.tracing.target_resolution import inspect_target


def fixture(tmp_path, *, aligned=True, include_v2=True):
    bb = "1111222233334444"
    other = "aaaabbbbccccdddd"
    bb_records = {
        bb: {"bb_id": bb, "function": "caller",
             "debug_locations": [{"file": "/build/src/vuln.c", "line": 42},
                                 {"file": "/build/src/vuln.c", "line": 99}]},
        other: {"bb_id": other, "function": "unrelated",
                "debug_locations": [{"file": "/build/src/other.c", "line": 100}]},
    }
    original = tmp_path / "before.jsonl"
    original.write_text("".join(json.dumps(row) + "\n" for row in [
        {"id": bb + ":0", "bb_id": bb, "function": "caller", "opcode": "load"},
        {"id": bb + ":1", "bb_id": bb, "function": "caller", "opcode": "store"},
        {"id": other + ":0", "bb_id": other, "function": "unrelated", "opcode": "load"},
    ]))
    v2 = tmp_path / "analysis_v2_nodes.jsonl"
    if include_v2:
        v2.write_text("".join(json.dumps(row) + "\n" for row in [
            {"id": bb + ":0", "kind": "instruction", "bb_id": bb,
             "function": "caller", "text": "load",
             "source_file": "/build/src/vuln.c", "line": 42,
             "inline_callsite_chain": [
                 {"file": "/build/src/caller.c", "line": 12, "column": 3}
             ]},
            {"id": bb + ":1", "kind": "instruction", "bb_id": bb,
             "function": "caller", "text": ("load" if not aligned else "store"),
             "source_file": "/build/src/vuln.c", "line": 99,
             "inline_callsite_chain": []},
            {"id": other + ":0", "kind": "instruction", "bb_id": other,
             "function": "unrelated", "text": "load",
             "source_file": "/build/src/other.c", "line": 100},
        ]))
    return bb_records, {bb}, original, v2


def inspect(tmp_path, *, aligned=True, include_v2=True):
    bb_records, executed, before, v2 = fixture(
        tmp_path, aligned=aligned, include_v2=include_v2
    )
    return inspect_target(
        bb_records, executed,
        {"relative_source_file": "src/vuln.c", "line": 42, "function": "vuln"},
        "1111222233334444:0",
        before,
        v2_nodes_path=v2,
    )


def test_each_instruction_requires_own_debug_location(tmp_path):
    result = inspect(tmp_path)
    assert result["status"] == "TARGET_EXECUTED"
    assert result["oracle_bb_count"] == 1
    assert result["v2_instruction_metadata_matched"] == 2
    assert result["exact_oracle_instruction_debugloc_matches"] == 1
    rows = {x["instruction_id"]: x for x in result["candidate_instructions"]}
    good = rows["1111222233334444:0"]
    bad = rows["1111222233334444:1"]
    assert good["instruction_exact_oracle_source_line"] is True
    assert good["inline_callsite_chain"][0]["line"] == 12
    assert bad["source_line_candidate"] is True  # same BB
    assert bad["instruction_exact_oracle_source_line"] is False
    assert bad["instruction_line"] == 99
    assert result["safe_for_automatic_retarget"] is False


def test_stale_v2_identity_cannot_supply_debug_location(tmp_path):
    report = inspect(tmp_path, aligned=False)
    rows = {x["instruction_id"]: x for x in report["candidate_instructions"]}
    assert rows["1111222233334444:1"]["v2_identity_mismatch"] is True
    assert "instruction_exact_oracle_source_line" not in rows["1111222233334444:1"]
    assert report["v2_instruction_metadata_matched"] == 1


def test_missing_v2_cannot_claim_per_instruction_debug_evidence(tmp_path):
    report = inspect(tmp_path, include_v2=False)
    assert report["inline_metadata_status"] == "V2_NODES_NOT_AVAILABLE"
    assert report["v2_instruction_metadata_matched"] == 0
    assert report["exact_oracle_instruction_debugloc_matches"] == 0
    assert all("instruction_exact_oracle_source_line" not in row
               for row in report["candidate_instructions"])

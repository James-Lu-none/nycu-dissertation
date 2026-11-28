"""BB DebugLoc union must not promote unrelated LLVM instructions."""
import json

from target_graph.tracing.target_resolution import inspect_target


def fixture(tmp_path):
    bb = "1111222233334444"
    other = "aaaabbbbccccdddd"
    bb_records = {
        bb: {"bb_id": bb, "function": "caller",
             "debug_locations": [{"file": "/build/src/vuln.c", "line": 42},
                                 {"file": "/build/src/vuln.c", "line": 99}]},
        other: {"bb_id": other, "function": "unrelated",
                "debug_locations": [{"file": "/build/src/other.c", "line": 100}]},
    }
    inst_map = tmp_path / "inst_map.jsonl"
    inst_map.write_text("".join(json.dumps(row) + "\n" for row in [
        {"inst_id": bb + ":0", "bb_id": bb, "function": "caller", "opcode": "load",
         "file": "/build/src/vuln.c", "line": 42,
         "inline_callsite_chain": [
             {"file": "/build/src/caller.c", "line": 12, "column": 3}
         ]},
        {"inst_id": bb + ":1", "bb_id": bb, "function": "caller", "opcode": "store",
         "file": "/build/src/vuln.c", "line": 99,
         "inline_callsite_chain": []},
        {"inst_id": other + ":0", "bb_id": other, "function": "unrelated", "opcode": "load",
         "file": "/build/src/other.c", "line": 100},
    ]))
    return bb_records, {bb}, inst_map


def test_each_instruction_requires_own_debug_location(tmp_path):
    bb_records, executed, inst_map = fixture(tmp_path)
    result = inspect_target(
        bb_records, executed,
        {"relative_source_file": "src/vuln.c", "line": 42, "function": "vuln"},
        "1111222233334444:0",
        inst_map,
    )
    assert result["status"] == "TARGET_EXECUTED"
    assert result["oracle_bb_count"] == 1
    assert result["inst_debugloc_metadata_matched"] == 2
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

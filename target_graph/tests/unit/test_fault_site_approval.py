"""Make manually reviewed crash-PC-to-LLVM target decisions auditable."""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_bento4_336_approved_faulting_store_matches_benchmark():
    case_id = "bento4-1.5.0_mp42aac_ASARUBBO-336"
    approval = json.loads(
        (ROOT / "configs/target_approvals" / f"{case_id}.json").read_text()
    )["cases"][case_id]
    entries = yaml.safe_load(
        (ROOT / "configs/projects/benchmark_30_cases.yaml").read_text()
    )["cases"]
    case = next(entry for entry in entries if entry["case_id"] == case_id)
    assert case["canonical_target_inst"] == approval["target_inst"]
    assert approval["target_inst"] == "002d55dafb123847:6"
    assert re.fullmatch(r"[0-9a-f]{16}:\d+", approval["target_inst"])

    # These are review-record consistency checks, not substitutes for a
    # fresh disassembly/hash verification of a locally rebuilt binary.
    assert approval["memory_access"] == "WRITE"
    assert approval["elf_type"] == "ET_EXEC"
    assert approval["faulting_machine_instruction"].startswith(
        f"{int(approval['fault_pc'], 16):x}:"
    )
    assert approval["immediate_hex"] in approval["faulting_machine_instruction"]
    assert approval["immediate_decimal"] == int(approval["immediate_hex"], 16)
    assert f"store i32 {approval['immediate_decimal']}" in approval["llvm_store"]
    assert approval["llvm_pointer_operand"] in approval["llvm_store"]
    assert approval["llvm_pointer_operand"] in approval["llvm_pointer_definition"]
    assert approval["native_svf_seed_count"] > 0
    for name in ("original_bitcode_sha256", "instrumented_binary_sha256",
                 "identity_tagged_bitcode_sha256", "crash_stderr_sha256"):
        assert re.fullmatch(r"[0-9a-f]{64}", approval[name])
    assert "EXPLORATORY_ONLY" in approval["review_conclusion"]

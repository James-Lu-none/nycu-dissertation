"""ASan fault PC review must preserve provenance and avoid false LLVM identity claims."""
from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/review_fault_pc.py"
spec = importlib.util.spec_from_file_location("fault_pc_review", SCRIPT)
assert spec and spec.loader
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


def test_parse_bento4_asan_write_to_null_offset():
    log = (
        "AddressSanitizer:DEADLYSIGNAL\n"
        "==8==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000008 "
        "(pc 0x000000552da2 bp 0x7fff sp 0x7fff T0)\n"
        "==8==The signal is caused by a WRITE memory access.\n"
        "#0 0x552da2 in AP4_Atom::SetType(unsigned int) /tmp/Ap4Atom.h:247:52\n"
    )
    crash = review.parse_asan_crash(log)
    assert crash["fault_pc"] == 0x552da2
    assert crash["access_address"] == 8
    assert crash["access_type"] == "WRITE"
    assert crash["sanitizer"] == "SEGV"
    assert "SetType" in crash["top_frame"]


def test_machine_instruction_must_start_exactly_at_pc():
    asm = (
        "  552d9e: 48 8b 40 08    mov rax,QWORD PTR [rax+0x8]\n"
        "  552da2: 89 50 08       mov DWORD PTR [rax+0x8],edx\n"
        "  552da5: c3             ret\n"
    )
    assert "mov DWORD PTR [rax+0x8],edx" in review.exact_pc_instruction(asm, 0x552da2)
    assert review.exact_pc_instruction(asm, 0x552da3) is None


def test_tagged_llvm_ir_resolves_real_instruction_metadata(tmp_path, monkeypatch):
    bc = tmp_path / "tagged.bc"
    bc.write_bytes(b"fake-for-mocked-llvm-dis")
    gep = "002d55dafb123847:5"
    store = "002d55dafb123847:6"

    def fake_dis(cmd, **kwargs):
        Path(cmd[cmd.index("-o") + 1]).write_text(
            "define void @main() {\n"
            "  %p = getelementptr i32, i32* %this, i64 2, !target_graph.dg.inst_id !101\n"
            "  store i32 %x, i32* %p, !target_graph.dg.inst_id !102\n"
            "}\n"
            f'!101 = !{{!"{gep}"}}\n'
            f'!102 = !{{!"{store}"}}\n'
        )
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(review.subprocess, "run", fake_dis)
    found = review.instruction_ir_from_tagged_bitcode(bc, [gep, store], "llvm-dis-14")
    assert "getelementptr" in found[gep]
    assert "store i32 %x" in found[store]
    assert not found[gep].startswith("store")


def test_stale_binary_cannot_be_used_for_pc_evidence(tmp_path):
    cid = "example"
    cdir = tmp_path / "cases" / cid
    cdir.mkdir(parents=True)
    binary = cdir / "prog_inst"
    binary.write_bytes(b"changed executable")
    (cdir / "prog.bc").write_bytes(b"bitcode")
    (cdir / "crash_stderr.txt").write_text(
        "ERROR: AddressSanitizer: SEGV on unknown address 0x8 "
        "(pc 0x552da2 bp 0x0 sp 0x0 T0)\n"
    )
    (cdir / "trace_run.json").write_text(json.dumps({
        "instrumented_binary_sha256": "0" * 64,
        "stderr_sha256": review.sha256_file(cdir / "crash_stderr.txt"),
        "bitcode_sha256": review.sha256_file(cdir / "prog.bc"),
    }))
    manifest = tmp_path / "benchmark.yaml"
    manifest.write_text("cases:\n  - case_id: example\n    target_binary: prog\n")
    with pytest.raises(ValueError, match="STALE_OR_MISSING_INSTRUMENTED_BINARY"):
        review.examine_case(cid, tmp_path / "cases", manifest)

"""Guard LLVM fault-site diagnostic against treating source/IR as binary PC proof."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "inspect_fault_pc", ROOT / "scripts/inspect_fault_pc.py"
)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


ASAN = """AddressSanitizer:DEADLYSIGNAL
==8==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000008 (pc 0x000000552da2 bp 0x7fff sp 0x7fff T0)
==8==The signal is caused by a WRITE memory access.
==8==Hint: address points to the zero page.
    #0 0x552da2 in AP4_Atom::SetType(unsigned int) /build/Ap4Atom.h:247:52
SUMMARY: AddressSanitizer: SEGV /build/Ap4Atom.h:247:52
"""


def test_read_write_fault_pc_and_top_frame():
    report = module.parse_asan_fault(ASAN)
    assert report["fault_pc"] == "0x000000552da2"
    assert report["fault_pc_int"] == 0x552da2
    assert report["fault_address"] == "0x000000000008"
    assert report["access_type"] == "WRITE"
    assert report["sanitizer_error"] == "SEGV"
    assert "SetType" in report["faulting_frame"]


def test_no_pc_is_not_inferred_from_source_line():
    with pytest.raises(ValueError, match="faulting PC"):
        module.parse_asan_fault("SUMMARY: AddressSanitizer: SEGV Ap4Atom.h:247")


def test_asm_only_selects_exact_pc_not_nearest_guess():
    disasm = """
  552d9f: lea    rax,[rbx+0x8]
  552da2: mov    DWORD PTR [rax],ecx
  552da5: ret
"""
    report = module.select_fault_instruction(disasm, 0x552da2)
    assert report["fault_pc_exact_instruction_boundary"]
    assert report["fault_instruction"]["mnemonic"] == "mov"
    assert "DWORD PTR [rax]" in report["fault_instruction"]["operands"]
    wrong = module.select_fault_instruction(disasm, 0x552da3)
    assert not wrong["fault_pc_exact_instruction_boundary"]
    assert wrong["fault_instruction"] is None


def test_original_ir_metadata_maps_gep_and_store_separately(tmp_path):
    gep, store = "002d55dafb123847:5", "002d55dafb123847:6"
    original = f"""define void @f(ptr %p, i32 %value) {{
entry:
  %field = getelementptr i8, ptr %p, i64 8, !target_graph.dg.inst_id !101
  store i32 %value, ptr %field, align 4, !target_graph.dg.inst_id !102
  ret void
}}
!101 = !{{!"{gep}"}}
!102 = !{{!"{store}"}}
"""
    p = tmp_path / "tagged.ll"
    p.write_text(original)
    report = module.locate_tagged_instructions_file(p, [gep, store])
    assert report["all_requested_found_once"]
    assert "getelementptr" in report["instructions"][gep][0]["ir"]
    assert "store" in report["instructions"][store][0]["ir"]
    assert report["instructions"][gep][0]["llvm_ir_line"] == 3
    assert report["instructions"][store][0]["llvm_ir_line"] == 4


def test_missing_metadata_cannot_claim_valid_original_ir(tmp_path):
    p = tmp_path / "tagged.ll"
    p.write_text("define void @foo() { ret void }\n")
    report = module.locate_tagged_instructions_file(
        p, ["002d55dafb123847:6"]
    )
    assert not report["all_requested_found_once"]
    assert report["instructions"]["002d55dafb123847:6"] == []

#!/usr/bin/env python3
"""Collect ASan fault-PC assembly and original tagged LLVM-IR evidence.

This tool is READ ONLY with respect to benchmark inputs, YAML, source, BC,
SVF and labels. Fault-PC disassembly of the ASan binary and instruction IDs
from the ORIGINAL tagged BC are related via debug-location/provenance, but
are *not* automatically asserted to be the same machine instruction.

Usage:
  python3 scripts/inspect_fault_pc.py \
    --case bento4-1.5.0_mp42aac_ASARUBBO-336 \
    --target-inst 002d55dafb123847:5 \
    --target-inst 002d55dafb123847:6
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]

_PC = re.compile(
    r"ERROR:\s*AddressSanitizer:\s*(\S+).*?\(\s*pc\s+(0x[0-9a-fA-F]+)",
    re.IGNORECASE,
)
_ACCESS = re.compile(r"The signal is caused by a (READ|WRITE) memory access", re.I)
_ADDR = re.compile(r"(?:on unknown address|on address)\s+(0x[0-9a-fA-F]+)", re.I)
_INSTRUCTION = re.compile(r"^\s*([0-9a-fA-F]+):\s+([a-zA-Z.][a-zA-Z0-9_.]*)\s*(.*?)\s*$")
_META_ID = re.compile(r"!target_graph\.dg\.inst_id\s+!(\d+)")
_META_VALUE = re.compile(r'^!(\d+)\s*=\s*!\{\s*!"([^"]+)"\s*\}\s*$')
_CASE_ID = re.compile(r"^[A-Za-z0-9_.-]+$")
_INST_ID = re.compile(r"^[0-9a-f]{16}:[0-9]+$")


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_asan_fault(stderr: str) -> dict[str, Any]:
    """Extract the observed process PC and memory access; no fault guesswork."""
    m = _PC.search(stderr)
    if not m:
        raise ValueError("ASan report does not contain a faulting PC")
    access = _ACCESS.search(stderr)
    addr = _ADDR.search(stderr)
    return {
        "sanitizer_error": m.group(1),
        "fault_pc": m.group(2),
        "fault_pc_int": int(m.group(2), 16),
        "access_type": access.group(1).upper() if access else None,
        "fault_address": addr.group(1) if addr else None,
        "faulting_frame": next(
            (line.strip() for line in stderr.splitlines()
             if re.match(r"^\s*#0\s", line)), None
        ),
    }


def select_fault_instruction(
    disassembly: str, fault_pc: int
) -> dict[str, Any]:
    """Select *exact* objdump instruction start, never a nearby guess."""
    nearby = []
    selected = None
    for line in disassembly.splitlines():
        m = _INSTRUCTION.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        rec = {
            "address": f"0x{addr:x}",
            "mnemonic": m.group(2),
            "operands": m.group(3),
            "raw_line": line.strip(),
        }
        nearby.append(rec)
        if addr == fault_pc:
            selected = rec
    return {
        "fault_pc_exact_instruction_boundary": selected is not None,
        "fault_instruction": selected,
        "nearby_instruction_count": len(nearby),
        "nearby_disassembly": nearby,
    }


def locate_tagged_instructions(
    llvm_ir: str, instruction_ids: list[str]
) -> dict[str, Any]:
    """Match DG identity metadata in textual LLVM IR to requested IDs.

    This intentionally uses original tagged.bc, NOT ASan-instrumented
    machine-code addresses. Only an analyst can correlate the two.
    """
    metadata = {}
    for line in llvm_ir.splitlines():
        m = _META_VALUE.match(line.strip())
        if m:
            metadata[m.group(1)] = m.group(2)
    requested = set(instruction_ids)
    found = {inst: [] for inst in instruction_ids}
    for lineno, line in enumerate(llvm_ir.splitlines(), 1):
        matches = _META_ID.findall(line)
        for md in matches:
            inst_id = metadata.get(md)
            if inst_id in requested:
                found[inst_id].append({"llvm_ir_line": lineno, "ir": line.strip()})
    return {
        "requested_instructions": instruction_ids,
        "instructions": found,
        "all_requested_found_once": all(len(found[x]) == 1 for x in instruction_ids),
    }


def run_tool(args: list[str], *, max_output: int = 20_000_000) -> str:
    completed = subprocess.run(
        args, check=False, capture_output=True, text=True,
        errors="replace", timeout=60
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"Tool {args[0]} failed (exit={completed.returncode}): "
            + completed.stderr[-1000:]
        )
    if len(completed.stdout) > max_output:
        raise ValueError("Tool output exceeds inspection size limit")
    return completed.stdout


def inspect(
    case_dir: Path, binary_name: str, instruction_ids: list[str],
    *, objdump: str = "objdump", llvm_dis: str = "llvm-dis-14",
    pc_window: int = 48,
) -> dict[str, Any]:
    case_dir = case_dir.resolve()
    binary = case_dir / (binary_name + "_inst")
    tagged_bc = case_dir / "svf_backend" / "tagged.bc"
    crash_file = case_dir / "crash_stderr.txt"
    for path in [binary, tagged_bc, crash_file]:
        if not path.is_file():
            raise FileNotFoundError(path)
    fault = parse_asan_fault(crash_file.read_text(encoding="utf-8", errors="replace"))
    pc = fault["fault_pc_int"]
    disassembly = run_tool([
        objdump, "-d", "-M", "intel", "--no-show-raw-insn",
        f"--start-address={max(0, pc-pc_window):#x}",
        f"--stop-address={pc+pc_window:#x}",
        str(binary)
    ])
    ir = run_tool([llvm_dis, "-o", "-", str(tagged_bc)])
    original = locate_tagged_instructions(ir, instruction_ids)
    return {
        "schema_version": 1,
        "analysis": "ASAN_MACHINE_PC_AND_ORIGINAL_LLVM_IR_DIAGNOSTIC_ONLY",
        "case_id": case_dir.name,
        "binary_sha256": file_sha(binary),
        "tagged_bitcode_sha256": file_sha(tagged_bc),
        "crash_stderr_sha256": file_sha(crash_file),
        "asan_fault": fault,
        "machine_code": select_fault_instruction(disassembly, pc),
        "original_llvm_ir": original,
        "mapping_claim": "NOT_VERIFIED: original IR and ASan binary require independent PC/operand matching",
        "fault_target_auto_approved": False,
        "notes": [
            "x86 address 0x8 may reflect NULL base + 8 field offset; register state not provided",
            "a BB-entry trace does not prove any particular instruction completed",
            "GEP is address computation; store is memory write",
            "SVFG mapped seeds are not proof that store pointer dependency was sliced",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True)
    parser.add_argument("--target-inst", required=True, action="append", dest="targets")
    parser.add_argument("--target-binary", default=None)
    parser.add_argument("--cases-root", type=Path, default=ROOT_DIR / "cases")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--llvm-dis", default=None)
    args = parser.parse_args()
    if not _CASE_ID.fullmatch(args.case):
        parser.error("invalid case ID")
    if not all(_INST_ID.fullmatch(x) for x in args.targets):
        parser.error("invalid LLVM instruction ID")
    case_dir = args.cases_root / args.case
    if args.target_binary:
        binary_name = args.target_binary
        if not _CASE_ID.fullmatch(binary_name):
            parser.error("invalid target binary name")
    else:
        binaries = [
            p.name[:-5] for p in case_dir.glob("*_inst") if p.is_file()
        ]
        if len(binaries) != 1:
            parser.error("expected one *_inst binary; use --target-binary")
        binary_name = binaries[0]
    llvm_dis = args.llvm_dis or shutil.which("llvm-dis-14") or shutil.which("llvm-dis")
    if not llvm_dis:
        parser.error("llvm-dis-14 (or llvm-dis) is required for original-IR inspection")
    report = inspect(case_dir, binary_name, args.targets,
                     objdump=args.objdump, llvm_dis=llvm_dis)
    output = args.output or case_dir / "fault_pc_evidence.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    print(f"Wrote {output}")
    print(f"ASan PC: {report['asan_fault']['fault_pc']} "
          f"access={report['asan_fault']['access_type']} "
          f"address={report['asan_fault']['fault_address']}")
    print("Exact machine instruction:",
          report["machine_code"]["fault_instruction"])
    print("Original LLVM IDs located:",
          report["original_llvm_ir"]["all_requested_found_once"])


if __name__ == "__main__":
    main()

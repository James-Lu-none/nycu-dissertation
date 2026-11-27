#!/usr/bin/env python3
"""Inspect an ASan fault PC against the *same* instrumented case binary.

This is diagnostic only. ASan's machine PC and a tagged LLVM instruction ID
are NOT inherently interchangeable. Do not auto-approve canonical targets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
_CRASH = re.compile(
    r"ERROR:\s*AddressSanitizer:\s*(?P<kind>[\w-]+)"
    r"\s+on\s+(?:unknown\s+)?address\s+(?P<address>0x[0-9a-fA-F]+)"
    r"\s*\(pc\s+(?P<pc>0x[0-9a-fA-F]+)",
    re.IGNORECASE,
)
_ACCESS = re.compile(r"The signal is caused by a\s+(READ|WRITE)\s+memory access", re.I)
_FRAME = re.compile(r"^\s*#0\s+.*$", re.M)
_ASM_LINE = re.compile(r"^\s*([0-9a-fA-F]+):\s+", re.M)
_IR_MD_USE = re.compile(r"!target_graph\.dg\.inst_id\s+!(\d+)")
_IR_MD_DEF = re.compile(r'^\s*!(\d+)\s*=\s*!\{!"([^"]+)"\}', re.M)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_asan_crash(stderr: str) -> dict[str, Any]:
    """Use the actual PC, not the symbolized source line, as machine evidence."""
    match = _CRASH.search(stderr)
    if not match:
        raise ValueError("No ASan ERROR record with a fault PC/address")
    access = _ACCESS.search(stderr)
    frame = _FRAME.search(stderr)
    return {
        "sanitizer": match["kind"],
        "fault_pc": int(match["pc"], 16),
        "fault_pc_hex": hex(int(match["pc"], 16)),
        "access_address": int(match["address"], 16),
        "access_address_hex": hex(int(match["address"], 16)),
        "access_type": access.group(1).upper() if access else None,
        "top_frame": frame.group().strip() if frame else None,
    }


def exact_pc_instruction(disassembly: str, pc: int) -> str | None:
    """Only an instruction that STARTS at PC counts as exact."""
    for line in disassembly.splitlines():
        match = _ASM_LINE.match(line)
        if match and int(match[1], 16) == pc:
            return line.strip()
    return None


def instruction_ir_from_tagged_bitcode(
    bitcode: Path, wanted_ids: list[str], llvm_dis: str,
) -> dict[str, str]:
    """Resolve tagged ID metadata to exact, unoptimized LLVM IR statements.

    llvm-dis writes to a temporary file so huge modules do not need to be
    captured in RAM. In a separate pass we decode the MDNode references and
    extract only the requested instruction lines.
    """
    if not wanted_ids or not bitcode.is_file():
        return {}
    with tempfile.TemporaryDirectory(prefix="targetgraph_ir_review_") as d:
        ll = Path(d) / "tagged.ll"
        subprocess.run(
            [llvm_dis, str(bitcode), "-o", str(ll)],
            check=True, capture_output=True, text=True,
        )
        wanted = set(wanted_ids)
        refs: dict[str, str] = {}
        with ll.open(encoding="utf-8", errors="replace") as file:
            for line in file:
                match = _IR_MD_DEF.match(line)
                if match and match[2] in wanted:
                    refs[match[1]] = match[2]
        found: dict[str, str] = {}
        with ll.open(encoding="utf-8", errors="replace") as file:
            for line in file:
                match = _IR_MD_USE.search(line)
                if match and match[1] in refs:
                    inst_id = refs[match[1]]
                    # Strip the metadata suffix; the ID is retained in JSON.
                    found[inst_id] = line.strip()
        return found


def load_case_metadata(case_id: str, manifest: Path) -> dict[str, Any]:
    config = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    matches = [c for c in config.get("cases", []) if c.get("case_id") == case_id]
    if len(matches) != 1:
        raise ValueError(f"Expected one case in manifest for {case_id}, found {len(matches)}")
    return matches[0]


def examine_case(
    case_id: str, cases_root: Path, manifest: Path,
    *, objdump: str | None = None, llvm_dis: str | None = None,
) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", case_id):
        raise ValueError("Invalid case ID")
    case = load_case_metadata(case_id, manifest)
    root = cases_root / case_id
    target_bin = case["target_binary"]
    binary = root / f"{target_bin}_inst"
    stderr_path = root / "crash_stderr.txt"
    run_path = root / "trace_run.json"
    if not all(p.is_file() for p in (binary, stderr_path, run_path)):
        raise FileNotFoundError("Need instrumented binary, crash_stderr.txt and trace_run.json")

    run = json.loads(run_path.read_text(encoding="utf-8"))
    required = {
        "instrumented_binary_sha256": binary,
        "stderr_sha256": stderr_path,
        "bitcode_sha256": root / f"{target_bin}.bc",
    }
    for label, path in required.items():
        if not path.is_file() or run.get(label) != sha256_file(path):
            raise ValueError(f"STALE_OR_MISSING_{label.upper()}: no analysis performed")

    crash = parse_asan_crash(stderr_path.read_text(encoding="utf-8", errors="replace"))
    report: dict[str, Any] = {
        "schema_version": 1,
        "case_id": case_id,
        "status": "EVIDENCE_COLLECTION_ONLY",
        "crash": crash,
        "instrumented_binary_sha256": sha256_file(binary),
        "bitcode_sha256": run["bitcode_sha256"],
        "faulting_pc_is_llvm_inst_id": False,
        "machine_pc_to_llvm_instruction_proven": False,
        "target_retargeted": False,
        "warnings": [
            "A BB-entry trace does not imply execution of each instruction in that BB",
            "The instrumented executable has ASan checks and may differ from original IR codegen",
            "GEP computes an address; only dereference/memory-access code can fault on WRITE",
            "Manual correlation of machine instruction, store pointer operand, and source is required",
        ],
    }

    objdump = objdump or shutil.which("objdump")
    if not objdump:
        report["disassembly_status"] = "OBJDUMP_NOT_FOUND"
    else:
        pc = crash["fault_pc"]
        cmd = [objdump, "-d", "-l", "-C", "-M", "intel",
               f"--start-address={max(0, pc - 128):#x}",
               f"--stop-address={pc + 96:#x}", str(binary)]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        report["disassembly_exit_code"] = proc.returncode
        if proc.returncode != 0:
            report["disassembly_status"] = "OBJDUMP_FAILED"
            report["disassembly_error"] = proc.stderr[-1200:]
        else:
            report["disassembly_status"] = "COMPLETE"
            report["machine_disassembly"] = proc.stdout
            report["machine_instruction_at_fault_pc"] = exact_pc_instruction(
                proc.stdout, pc
            )
            if report["machine_instruction_at_fault_pc"] is None:
                report["warnings"].append(
                    "No exact instruction at ASan PC in disassembly; check PIE/load bias or binary mismatch"
                )

    calibration_path = root / "target_calibration.json"
    wanted_ids: list[str] = []
    if calibration_path.is_file():
        calibration = json.loads(calibration_path.read_text(encoding="utf-8"))
        rows = calibration.get("candidate_instruction_evidence") or []
        wanted_ids = [
            row["instruction_id"] for row in rows
            if isinstance(row, dict) and isinstance(row.get("instruction_id"), str)
        ]
        report["candidate_evidence"] = rows
        report["svfg_probe"] = calibration.get("svfg_candidate_probe")
        report["faulting_access_review"] = calibration.get("faulting_access_review")
    tagged = root / "svf_backend" / "tagged.bc"
    llvm_dis = llvm_dis or shutil.which("llvm-dis-14") or shutil.which("llvm-dis")
    if llvm_dis and tagged.is_file() and wanted_ids:
        try:
            report["candidate_original_llvm_ir"] = instruction_ir_from_tagged_bitcode(
                tagged, wanted_ids, llvm_dis,
            )
            missing = sorted(set(wanted_ids) - set(report["candidate_original_llvm_ir"]))
            if missing:
                report["warnings"].append(
                    "Candidate IDs absent from tagged LLVM IR: " + ", ".join(missing)
                )
        except (OSError, subprocess.CalledProcessError) as exc:
            report["ir_extraction_error"] = str(exc)
    else:
        report["ir_extraction_status"] = "LLVM_DIS_OR_TAGGED_BC_OR_CANDIDATES_MISSING"
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True)
    parser.add_argument("--manifest", type=Path,
                        default=ROOT / "configs/projects/benchmark_30_cases.yaml")
    parser.add_argument("--cases-root", type=Path, default=ROOT / "cases")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = examine_case(args.case, args.cases_root, args.manifest)
    output = args.output or args.cases_root / args.case / "fault_pc_review.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    print(f"Wrote {output}")
    print(f"ASan PC={report['crash']['fault_pc_hex']} "
          f"access={report['crash']['access_type']} "
          f"address={report['crash']['access_address_hex']}")
    print("Machine instruction:", report.get("machine_instruction_at_fault_pc"))
    print("No target has been changed.")


if __name__ == "__main__":
    main()

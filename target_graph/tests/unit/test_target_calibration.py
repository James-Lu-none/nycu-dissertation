"""Calibration must not auto-apply SVFG-compatible but unverified targets."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from target_graph.tracing.evidence import sha256


ROOT = Path(__file__).resolve().parents[2]


def calibration():
    spec = importlib.util.spec_from_file_location(
        "targetgraph_calibration", ROOT / "scripts/calibrate_targets.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_explicit_approval_requires_faulting_operand_review(tmp_path):
    target = tmp_path / "approved.json"
    target.write_text(json.dumps({"cases": {
        "sample": {"target_inst": "abcdef0123456789:2",
                   "faulting_instruction_evidence":
                       "ASan PC 0x1234, llvm DebugLoc inlinedAt, memory load operand"}
    }}))
    assert calibration()._approved_targets(target)["sample"]["target_inst"] == (
        "abcdef0123456789:2"
    )
    target.write_text(json.dumps({"cases": {
        "sample": {"target_inst": "abcdef0123456789:2"}
    }}))
    with pytest.raises(ValueError, match="faulting_instruction_evidence"):
        calibration()._approved_targets(target)


def test_apply_flag_cannot_silently_use_heuristic_proposals():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts/calibrate_targets.py"), "--apply"],
        capture_output=True, text=True,
    )
    assert proc.returncode != 0
    assert "--approved-targets" in proc.stderr


def test_calibration_requires_matching_direct_trace_and_sanitizer(tmp_path):
    case_id = "fixture"
    cdir = tmp_path / case_id
    cdir.mkdir()
    (cdir / "src").mkdir()
    source = cdir / "src/vuln.c"
    source.write_text("void crash(void) {}\n")
    bc = cdir / "demo.bc"
    bc.write_bytes(b"bitcode")
    binary = cdir / "demo_inst"
    binary.write_bytes(b"instrumented")
    poc = cdir / "poc"
    poc.write_bytes(b"poc bytes")
    bb_map = cdir / "bb_map.jsonl"
    bb_map.write_text(json.dumps({
        "bb_id": "aaaabbbbccccdddd",
        "function": "crash",
        "debug_locations": [{"file": "/tmp/vuln.c", "line": 42}],
    }) + "\n")
    trace_raw = cdir / "trace_crash.txt"
    trace_raw.write_text("0: aaaabbbbccccdddd\n")
    stderr = cdir / "crash_stderr.txt"
    stderr.write_text(
        "ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "#0 0xabcd in crash /tmp/./vuln.c:42:4\n"
    )
    checks = {
        "bitcode_sha256": bc,
        "instrumented_binary_sha256": binary,
        "poc_sha256": poc,
        "trace_file_sha256": trace_raw,
    }
    payload = {key: sha256(path) for key, path in checks.items()}
    (cdir / "trace_bbs.json").write_text(json.dumps({
        "schema_version": 2,
        "case_id": case_id,
        "trace_mode": "direct_bb_id",
        "executed_bbs_unique": ["aaaabbbbccccdddd"],
        "bb_map_sha256": sha256(bb_map),
        **payload,
    }))
    (cdir / "trace_run.json").write_text(json.dumps({
        "case_id": case_id,
        "poc_exit_code": 1,
        "stderr_sha256": sha256(stderr),
        **payload,
    }))
    meta = {
        "case_id": case_id,
        "target_binary": "demo",
        "expected_oracle": {
            "sanitizer": "heap-buffer-overflow",
            "relative_source_file": "vuln.c",
            "line": 42, "function": "crash",
            "source_file_sha256": sha256(source),
        },
    }
    good, error = calibration()._execution_evidence(meta, cdir, bc)
    assert good == {"aaaabbbbccccdddd"}
    assert error is None
    bc.write_bytes(b"different bitcode")
    bad, error = calibration()._execution_evidence(meta, cdir, bc)
    assert not bad
    assert error == "STALE_BITCODE_SHA256"

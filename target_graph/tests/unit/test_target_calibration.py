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



def test_native_probe_reports_both_gep_and_store_from_one_svfg(tmp_path, monkeypatch):
    """First compatible GEP is not proof of a faulting store."""
    mod = calibration()
    monkeypatch.setattr(mod, "ROOT_DIR", tmp_path)
    case_id = "bento4_fixture"
    out = tmp_path / "cases" / case_id / "svf_backend"
    out.mkdir(parents=True)
    gep = "002d55dafb123847:5"
    store = "002d55dafb123847:6"

    def run_native(*args, **kwargs):
        (out / "test_svfg.json").write_text(json.dumps({
            "backend": "SVF-2.9/SVFG",
            "analysis": "BACKWARD_VALUE_FLOW_ONLY",
            "status": "EXPLORATORY_ONLY",
            "target": gep,
            "target_seed_svfg_ids": [10],
            "svfg_nodes": [{"svfg_id": 10, "instruction_id": gep}],
            "candidate_seed_counts": [
                {"instruction_id": gep, "svfg_seed_count": 1},
                {"instruction_id": store, "svfg_seed_count": 2},
            ],
        }))
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(mod.subprocess, "run", run_native)
    details = {}
    chosen = mod.test_target_candidates(
        case_id, [gep, store], probe_details=details
    )
    assert chosen == gep
    assert details["status"] == "SVFG_PROBE_COMPLETE_EXPLORATORY_ONLY"
    assert details["svfg_compatible_candidates"] == [gep, store]
    assert [row["svfg_seed_count"] for row in
            details["candidate_seed_counts"]] == [1, 2]
    assert "not verify" in details["warning"]


def test_native_probe_rejects_failed_process_even_with_old_report(tmp_path, monkeypatch):
    mod = calibration()
    monkeypatch.setattr(mod, "ROOT_DIR", tmp_path)
    out = tmp_path / "cases" / "fixture" / "svf_backend"
    out.mkdir(parents=True)
    stale = out / "test_svfg.json"
    stale.write_text('{"target":"0000000000000000:0"}')

    def failed_run(*args, **kwargs):
        return subprocess.CompletedProcess([], 134, "Resolved target instruction: old", "")

    monkeypatch.setattr(mod.subprocess, "run", failed_run)
    details = {}
    assert mod.test_target_candidates(
        "fixture", ["1111222233334444:0"], probe_details=details
    ) is None
    assert details["native_exit_code"] == 134
    assert details["status"] == "NATIVE_PROBE_FAILED"
    assert not stale.exists()


def test_native_probe_rejects_old_backend_without_candidate_counters(tmp_path, monkeypatch):
    mod = calibration()
    monkeypatch.setattr(mod, "ROOT_DIR", tmp_path)
    out = tmp_path / "cases" / "fixture" / "svf_backend"
    out.mkdir(parents=True)

    def old_backend(*args, **kwargs):
        (out / "test_svfg.json").write_text(json.dumps({
            "backend": "SVF-2.9/SVFG",
            "analysis": "BACKWARD_VALUE_FLOW_ONLY",
            "status": "EXPLORATORY_ONLY",
            "target": "1111222233334444:0",
            "target_seed_svfg_ids": [1],
            "svfg_nodes": [{"svfg_id": 1, "instruction_id": "1111222233334444:0"}],
        }))
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(mod.subprocess, "run", old_backend)
    details = {}
    assert mod.test_target_candidates(
        "fixture", ["1111222233334444:0"], probe_details=details
    ) is None
    assert details["status"] == "NATIVE_REPORT_INVALID"
    assert "rebuild" in details["error"]



def test_review_prefers_faulting_memory_access_over_first_gep_seed():
    """Bento4-336: both seeds exist, but a GEP is not itself a dereference."""
    gep = "002d55dafb123847:5"
    store = "002d55dafb123847:6"
    report = calibration().review_memory_access_candidates([
        {"instruction_id": gep, "fault_site_role": "ADDRESS_COMPUTATION"},
        {"instruction_id": store, "fault_site_role": "DIRECT_MEMORY_ACCESS"},
    ], {"svfg_compatible_candidates": [gep, store]})
    assert report["memory_access_review_candidates"] == [store]
    assert report["manual_review_order"] == [store, gep]
    assert report["single_memory_access_hypothesis"] == store
    assert report["requires_fault_pc_operand_verification"]
    assert report["memory_access_priority_is_not_ground_truth"]


def test_review_does_not_pick_arbitrary_memory_access_among_multiple():
    load, store = "1111222233334444:1", "1111222233334444:2"
    report = calibration().review_memory_access_candidates([
        {"instruction_id": load, "fault_site_role": "DIRECT_MEMORY_ACCESS"},
        {"instruction_id": store, "fault_site_role": "DIRECT_MEMORY_ACCESS"},
    ], {"svfg_compatible_candidates": [load, store]})
    assert report["memory_access_review_candidates"] == [load, store]
    assert report["single_memory_access_hypothesis"] is None


def test_review_excludes_memory_access_without_native_seed():
    gep, store = "1111222233334444:3", "1111222233334444:4"
    report = calibration().review_memory_access_candidates([
        {"instruction_id": gep, "fault_site_role": "ADDRESS_COMPUTATION"},
        {"instruction_id": store, "fault_site_role": "DIRECT_MEMORY_ACCESS"},
    ], {"svfg_compatible_candidates": [gep]})
    assert report["memory_access_review_candidates"] == []
    assert report["single_memory_access_hypothesis"] is None

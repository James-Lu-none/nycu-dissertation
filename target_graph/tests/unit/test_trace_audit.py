"""Fail-closed validation of LLVM-native BB trace and SVF weak-label evidence."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from target_graph.tracing.evidence import sha256, asan_evidence
from target_graph.tracing.symbolizer import parse_trace_bb_ids


ROOT = Path(__file__).resolve().parents[2]


def _script(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def specimen(tmp_path):
    case_id = "example-vuln"
    cdir = tmp_path / case_id
    cdir.mkdir()
    (cdir / "src" / "src").mkdir(parents=True)
    source = cdir / "src/src/vuln.c"
    source.write_text("void fault(char *p) { *p = 1; }\n", encoding="utf-8")
    bc = cdir / "prog.bc"
    bc.write_bytes(b"original LLVM-bitcode fixture")
    instrumented = cdir / "prog_inst"
    instrumented.write_bytes(b"original LLVM trace binary")
    poc = cdir / "poc"
    poc.write_bytes(b"crash data")
    bbs = ["aaaabbbbccccdddd", "1111222233334444"]
    bb_map = cdir / "bb_map.jsonl"
    bb_map.write_text(
        json.dumps({"bb_id": bbs[0], "function": "fault",
                    "debug_locations": [{"file": "/build/src/vuln.c", "line": 12}]})
        + "\n" + json.dumps({"bb_id": bbs[1], "function": "main",
                              "debug_locations": []}) + "\n", encoding="utf-8",
    )
    trace = cdir / "trace_crash.txt"
    trace.write_text(f"0: {bbs[1]}\n1: {bbs[0]}\n", encoding="utf-8")
    stderr = cdir / "crash_stderr.txt"
    stderr.write_text(
        "==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0\n"
        "    #0 0x5288a6 in fault /build/src/vuln.c:12:3\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow /build/src/vuln.c:12\n",
        encoding="utf-8",
    )
    meta = {
        "case_id": case_id, "target_binary": "prog",
        "canonical_target_inst": bbs[0] + ":0",
        "expected_oracle": {
            "sanitizer": "heap-buffer-overflow",
            "relative_source_file": "src/vuln.c",
            "line": 12,
            "function": "fault",
            "source_file_sha256": sha256(source),
        },
    }
    run_trace = _script("run_trace.py", "trace_module")
    trace_json = run_trace.write_trace_bbs_json(case_id, cdir, instrumented, trace)
    trace_run = {
        "case_id": case_id,
        "poc_exit_code": 1,
        "instrumented_binary_sha256": sha256(instrumented),
        "bitcode_sha256": sha256(bc),
        "poc_sha256": sha256(poc),
        "stderr_sha256": sha256(stderr),
        "trace_file_sha256": sha256(trace),
    }
    (cdir / "trace_run.json").write_text(json.dumps(trace_run), encoding="utf-8")
    svf_dir = cdir / "svf_backend"
    svf_dir.mkdir()
    svf = {
        "backend": "SVF-2.9/SVFG",
        "analysis": "BACKWARD_VALUE_FLOW_ONLY",
        "status": "EXPLORATORY_ONLY",
        "validated_for_supervision": False,
        "target": meta["canonical_target_inst"],
        "original_bitcode_sha256": sha256(bc),
        "instruction_ids": [meta["canonical_target_inst"]],
        "basic_blocks": bbs,
    }
    (svf_dir / "svf_slice.json").write_text(json.dumps(svf), encoding="utf-8")
    return meta, tmp_path, cdir, bbs


def audit(meta, root):
    return _script("audit_and_label.py", "audit_module").audit_and_label_case(meta, root)


def test_direct_llvm_bb_trace_has_no_source_expansion(specimen):
    meta, root, cdir, bbs = specimen
    trace = json.loads((cdir / "trace_bbs.json").read_text())
    assert trace["trace_mode"] == "direct_bb_id"
    assert trace["total_bb_events"] == 2
    assert trace["executed_bbs_unique"] == [bbs[1], bbs[0]]
    r = audit(meta, root)
    assert r["status"] == "PASSED"
    assert r["crash_reproduced"] is True
    assert r["bitcode_sha_verified"] is True
    labels = json.loads((cdir / "svf_weak_labels.json").read_text())
    assert labels["weak_positive_bbs"] == sorted(bbs)
    assert labels["verified_negative_bbs"] == []
    assert labels["supervision_validated"] is False


def test_stale_svf_bitcode_fails_and_deletes_old_labels(specimen):
    meta, root, cdir, _ = specimen
    assert audit(meta, root)["status"] == "PASSED"
    svf_path = cdir / "svf_backend/svf_slice.json"
    payload = json.loads(svf_path.read_text())
    payload["original_bitcode_sha256"] = "0" * 64
    svf_path.write_text(json.dumps(payload))
    result = audit(meta, root)
    assert result["failure_reason"] == "SVF_BITCODE_HASH_MISMATCH"
    assert not (cdir / "svf_weak_labels.json").exists()


def test_legacy_trace_and_wrong_target_rejected(specimen):
    meta, root, cdir, bbs = specimen
    payload = json.loads((cdir / "trace_bbs.json").read_text())
    payload["trace_mode"] = "pc_symbolize"
    (cdir / "trace_bbs.json").write_text(json.dumps(payload))
    assert audit(meta, root)["failure_reason"] == "TRACE_NOT_DIRECT_BB_ID"
    payload["trace_mode"] = "direct_bb_id"
    (cdir / "trace_bbs.json").write_text(json.dumps(payload))
    meta["canonical_target_inst"] = "ffffaaaaffffaaaa:0"
    assert audit(meta, root)["failure_reason"] == "TARGET_BB_NOT_HIT_IN_DIRECT_TRACE"


def test_source_mismatch_and_empty_intersection_rejected(specimen):
    meta, root, cdir, bbs = specimen
    source = cdir / "src/src/vuln.c"
    source.write_text("not the compiled original")
    assert audit(meta, root)["failure_reason"] == "SOURCE_PROVENANCE_HASH_MISMATCH"
    source.write_text("void fault(char *p) { *p = 1; }\n")
    data_path = cdir / "svf_backend/svf_slice.json"
    data = json.loads(data_path.read_text())
    data["basic_blocks"] = []
    data_path.write_text(json.dumps(data))
    assert audit(meta, root)["failure_reason"] == "SVF_TARGET_BB_MISSING"


def test_asandata_must_match_specific_frame_and_line():
    good = ("ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "#0 0xabc in fault /build/src/vuln.c:12:3\n")
    oracle = {"sanitizer": "heap-buffer-overflow",
              "relative_source_file": "src/vuln.c",
              "line": 12, "function": "fault"}
    assert asan_evidence(good, oracle)["crash_reproduced"]
    assert not asan_evidence(good.replace(":12:", ":13:"), oracle)["crash_reproduced"]
    assert not asan_evidence(good.replace("fault ", "other "), oracle)["crash_reproduced"]


def test_parser_rejects_mixed_and_discontinuous_events(tmp_path):
    f = tmp_path / "trace.txt"
    f.write_text("0: 0123456789abcdef\n1: abcdef0123456789\n")
    assert parse_trace_bb_ids(f) == ["0123456789abcdef", "abcdef0123456789"]
    f.write_text("0: 0123456789abcdef\n1: 0xabc\n")
    with pytest.raises(ValueError, match="Mixed"):
        parse_trace_bb_ids(f)
    f.write_text("0: 0123456789abcdef\n3: 0123456789abcdef\n")
    with pytest.raises(ValueError, match="Discontinuous"):
        parse_trace_bb_ids(f)


def test_direct_trace_refuses_unknown_bb_identity(specimen):
    meta, root, cdir, _ = specimen
    trace = cdir / "trace_crash.txt"
    trace.write_text("0: fedcfedcfedcfedc\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing from bb_map"):
        _script("run_trace.py", "trace_module").write_trace_bbs_json(
            meta["case_id"], cdir, cdir / "prog_inst", trace
        )

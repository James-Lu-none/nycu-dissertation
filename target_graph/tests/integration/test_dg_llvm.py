"""Optional end-to-end DG/LLVM14 smoke test, including metadata preservation."""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from target_graph.dg.validate import validate_survivors


@pytest.mark.skipif(
    os.getenv("DG_LLVM14_DOCKER") != "1" or shutil.which("docker") is None,
    reason="Set DG_LLVM14_DOCKER=1 and build target-graph:dg-llvm14",
)
def test_dg_slicer_survivors_retain_original_llvm_ids(tmp_path):
    # Direct-call criterion. PoC target-site identity is a separate
    # acceptance gate, NOT proven by this smoke test.
    fixture = tmp_path / "sample.c"
    fixture.write_text(
        "volatile int sink_value;\n"
        "__attribute__((noinline)) void sink(int n) { sink_value=n; }\n"
        "int main(void) { int x=2; sink(x+1); return 0; }\n",
        encoding="utf-8",
    )
    cmd = [
        "docker", "run", "--rm", "--user",
        f"{os.getuid()}:{os.getgid()}",
        "-v", f"{tmp_path}:/data",
        "-e", "TARGET_GRAPH_BUILD_ID=dg_fixture",
        "target-graph:dg-llvm14", "bash", "-c",
        "set -euo pipefail; "
        "clang -O0 -g -fno-inline -emit-llvm -c /data/sample.c -o /data/original.bc; "
        "opt -load-pass-plugin=/usr/local/lib/DGIdentityPass.so "
        "-passes=dg-tag -o /data/tagged.bc /data/original.bc; "
        "TARGET_GRAPH_DG_EXPORT=/data/before.jsonl "
        "opt -load-pass-plugin=/usr/local/lib/DGIdentityPass.so "
        "-passes=dg-export -disable-output /data/tagged.bc; "
        "llvm-slicer -entry main -c sink -o /data/sliced.bc /data/tagged.bc; "
        "TARGET_GRAPH_DG_EXPORT=/data/after.jsonl "
        "opt -load-pass-plugin=/usr/local/lib/DGIdentityPass.so "
        "-passes=dg-export -disable-output /data/sliced.bc",
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    assert completed.returncode == 0, completed.stdout + "\n" + completed.stderr
    before = [
        json.loads(row) for row in (tmp_path / "before.jsonl").read_text().splitlines()
    ]
    calls = [
        row["id"] for row in before
        if row["function"] == "main" and row["opcode"] == "call"
    ]
    assert len(calls) == 1
    report = validate_survivors(
        tmp_path / "before.jsonl", tmp_path / "after.jsonl",
        calls[0], criterion="sink", source_bc=tmp_path / "original.bc"
    )
    assert calls[0] in report["instruction_ids"]
    assert not report["validated_for_supervision"]

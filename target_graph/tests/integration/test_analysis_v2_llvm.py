"""Docker/LLVM14 integration regression; opt in via ANALYSIS_V2_DOCKER=1."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest

from target_graph.analysis_v2.graph import DependencyGraph
from target_graph.analysis_v2.slicing import backward_slice


@pytest.mark.skipif(
    os.getenv("ANALYSIS_V2_DOCKER") != "1" or shutil.which("docker") is None,
    reason="Requires ANALYSIS_V2_DOCKER=1 and target-graph:llvm14 Docker image",
)
def test_llvm_pass_does_not_infer_unused_argument_return_dependence(tmp_path):
    root = Path(__file__).resolve().parents[2]
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{root}:/workspace:ro",
        "-v", f"{tmp_path}:/output",
        "-e", "TARGET_GRAPH_BUILD_ID=v2_fixture",
        "-e", "TARGET_GRAPH_OUT_DIR=/output",
        "target-graph:llvm14",
        "bash", "-c",
        "set -euo pipefail; "
        "clang -g -O1 -fno-inline -emit-llvm -c "
        "/workspace/tests/fixtures/analysis_v2/no_false_dep.c "
        "-o /output/fixture.bc; "
        "opt -load-pass-plugin=/usr/local/lib/AnalysisV2Pass.so "
        "-passes=analysis-v2 -disable-output /output/fixture.bc",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stdout + "\n" + result.stderr

    graph = DependencyGraph.from_directory(tmp_path)
    call_sites = [
        node for node in graph.nodes.values()
        if node.kind == "instruction" and node.function == "caller"
        and node.text == "call"
    ]
    assert len(call_sites) == 1
    call_result = call_sites[0].id + ":result"
    assert call_result in graph.nodes

    slice_result = backward_slice(graph, call_result)
    formal_ids = {
        node.text: node.id
        for node in graph.nodes.values()
        if node.function == "only_first" and node.kind == "formal"
    }
    assert formal_ids["arg#0"] in slice_result.nodes
    assert formal_ids["arg#1"] not in slice_result.nodes

    # The callsite was actually mapped to its caller argument value.
    caller_formals = [
        n for n in graph.nodes.values()
        if n.kind == "formal" and n.function == "caller"
    ]
    assert len(caller_formals) == 2
    assert any(n.id in slice_result.nodes for n in caller_formals)
    assert not slice_result.validated_for_supervision

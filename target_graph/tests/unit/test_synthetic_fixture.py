"""Unit and integration test for Milestone 1: Synthetic C Fixture."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
import pandas as pd
import pytest
import torch

from target_graph.analysis.export import export_raw_to_parquet
from target_graph.graphs.loader import load_program_graph_to_pyg
from target_graph.graphs.relations import CANONICAL_RELATION_TO_ID
from target_graph.graphs.validate import validate_graph_bundle
from target_graph.labels.slicing import partition_target_candidates
from target_graph.llvm.mapping import BasicBlockMapper
from target_graph.models.heads import TargetConditionedRanker
from target_graph.models.losses import pairwise_ranking_loss
from target_graph.models.rgcn import ProgramRGCN
from target_graph.tracing.sanitizer import parse_sanitizer_output
from target_graph.tracing.symbolizer import trace_to_basic_blocks

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "synthetic"
BUILD_DIR = FIXTURE_DIR / "build"
PARQUET_DIR = FIXTURE_DIR / "parquet"


def test_synthetic_fixture_build_and_run():
    """Milestone 1 Acceptance Test:
    
    Asserts:
    1. Docker compiles bitcode and runs LLVM New-PM TargetGraphPass plugin.
    2. bb_map.jsonl, raw_nodes.jsonl, raw_edges.jsonl emitted.
    3. Instrumented ASan binary runs: safe passes with 0, crash produces ASan report.
    4. Ordered traces captured for both runs.
    5. Parquet graph tables export and pass all referential integrity checks.
    6. Multi-relational graph contains CFG, CDG, DDG_SSA, CALL, RETURN.
    7. Sanitizer fault maps to target BB.
    8. Backward slice S_t, executed E_t, and weak positive P_t = E_t & S_t are non-empty.
    9. R-GCN forward pass and ranking computation execute without errors.
    """
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    PARQUET_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Run build_and_run.sh inside target-graph:llvm14 container
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{ROOT}:/workspace",
        "-w", "/workspace",
        "target-graph:llvm14",
        "/workspace/tests/fixtures/synthetic/build_and_run.sh",
        "/workspace/tests/fixtures/synthetic/build",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Build script failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"

    # 2. Check emitted raw artifacts
    assert (BUILD_DIR / "bb_map.jsonl").exists(), "Missing bb_map.jsonl"
    assert (BUILD_DIR / "raw_nodes.jsonl").exists(), "Missing raw_nodes.jsonl"
    assert (BUILD_DIR / "raw_edges.jsonl").exists(), "Missing raw_edges.jsonl"
    assert (BUILD_DIR / "trace_safe.txt").exists(), "Missing trace_safe.txt"
    assert (BUILD_DIR / "trace_crash.txt").exists(), "Missing trace_crash.txt"
    assert (BUILD_DIR / "crash_stderr.txt").exists(), "Missing crash_stderr.txt"

    # 3. Check sanitizer output
    crash_stderr = (BUILD_DIR / "crash_stderr.txt").read_text()
    san_report = parse_sanitizer_output(crash_stderr)
    assert san_report is not None, f"Failed to parse ASan report from stderr:\n{crash_stderr}"
    assert "heap-buffer-overflow" in san_report.error_type
    assert san_report.crash_frame is not None
    assert san_report.crash_frame.function_name == "process_and_fault"

    # 4. Export to canonical Parquet tables
    stats = export_raw_to_parquet(
        raw_dir=BUILD_DIR,
        output_dir=PARQUET_DIR,
        build_id="synthetic_v1",
        ir_hash="synthetic_ir_test",
        llvm_version="14.0.0",
    )
    assert stats["num_nodes"] > 0
    assert stats["num_edges"] > 0

    # 5. Validate graph bundle
    validate_graph_bundle(PARQUET_DIR)

    edges_df = pd.read_parquet(PARQUET_DIR / "edges.parquet")
    nodes_df = pd.read_parquet(PARQUET_DIR / "nodes.parquet")

    # Verify relation types exist in synthetic program:
    relation_ids = set(edges_df["relation_id"].unique())
    # CFG edges must exist
    assert CANONICAL_RELATION_TO_ID["CFG_T"] in relation_ids
    assert CANONICAL_RELATION_TO_ID["CFG_F"] in relation_ids
    assert CANONICAL_RELATION_TO_ID["CFG_NEXT"] in relation_ids
    # CDG (control dependence) must exist
    assert CANONICAL_RELATION_TO_ID["CDG"] in relation_ids
    # SSA def-use must exist
    assert CANONICAL_RELATION_TO_ID["DDG_SSA"] in relation_ids
    # Interprocedural CALL & RETURN must exist
    assert CANONICAL_RELATION_TO_ID["CALL"] in relation_ids
    assert CANONICAL_RELATION_TO_ID["RETURN"] in relation_ids

    # 6. Basic Block Mapper: Map crash site to target BB
    mapper = BasicBlockMapper(BUILD_DIR / "bb_map.jsonl")
    fault_line = san_report.crash_frame.line_number
    candidate_target_bbs = mapper.map_source_location("synthetic_target.c", fault_line)
    assert len(candidate_target_bbs) > 0, f"Could not map crash line {fault_line} to any BB"
    target_bb = candidate_target_bbs[0]

    # 7. Slicing and Candidate Partition from symbol-mapped execution trace
    all_bbs = set(nodes_df["bb_id"].unique())
    executed_bbs = trace_to_basic_blocks(
        trace_file=BUILD_DIR / "trace_crash.txt",
        binary_path=BUILD_DIR / "synthetic_target",
        bb_mapper=mapper,
    )
    assert len(executed_bbs) > 0, "Executed trace BBs must not be empty"

    partition = partition_target_candidates(
        all_bbs=all_bbs,
        executed_trace_bbs=executed_bbs,
        edges_df=edges_df,
        target_bb=target_bb,
    )

    assert target_bb in partition.P_t, "Target BB must be in weak positive partition P_t"
    assert len(partition.S_t) >= 1, "Backward slice must contain at least the target BB"
    assert len(partition.P_t) >= 1, "Weak positive set P_t must not be empty"

    # 8. Test PyG Loading and Model Forward Pass
    pyg_data, bb_to_idx = load_program_graph_to_pyg(PARQUET_DIR, include_reverse_edges=False)
    assert pyg_data.num_nodes == len(all_bbs)
    assert pyg_data.edge_index.size(1) == len(edges_df)

    # Synthetic node features (in place of Qwen embeddings for smoke test)
    dummy_x = torch.randn(pyg_data.num_nodes, 3584)
    model = ProgramRGCN(in_dim=3584, hidden_dim=64, num_layers=2, num_relations=pyg_data.num_relations)
    h = model(dummy_x, pyg_data.edge_index, pyg_data.edge_type)
    assert h.shape == (pyg_data.num_nodes, 64)

    # Ranker test
    ranker = TargetConditionedRanker(node_dim=64, dist_embed_dim=16, mlp_hidden_dim=32)
    target_idx = bb_to_idx[target_bb]
    h_target = h[target_idx:target_idx+1]
    dist_buckets = torch.zeros(pyg_data.num_nodes, dtype=torch.long)
    scores = ranker(h, h_target, dist_buckets)
    assert scores.shape == (pyg_data.num_nodes,)

    print(f"\n[SUCCESS] Milestone 1 verified! Nodes: {len(all_bbs)}, Edges: {len(edges_df)}, Target BB: {target_bb}")

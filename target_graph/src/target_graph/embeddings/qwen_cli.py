"""CLI entrypoint for Qwen embedding extraction."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import pandas as pd
import torch

from target_graph.embeddings.cache import EmbeddingCache
from target_graph.embeddings.qwen import QwenEmbeddingPipeline, QwenExtractorConfig
from target_graph.graphs.schema import SourceSpan


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract and cache Qwen basic block embeddings.")
    parser.add_argument("--case", required=True, help="Case identifier (or 'synthetic')")
    parser.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B", help="Model name or path")
    parser.add_argument("--layer", type=int, default=14, help="Transformer layer index (7, 14, 21, 28)")
    parser.add_argument("--cache-dir", default="cache/embeddings", help="Cache directory")
    parser.add_argument("--chunk-policy", default="chunk", choices=["chunk", "exclude"], help="Long function policy")
    parser.add_argument("--mock", action="store_true", help="Use deterministic mock CPU extractor")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[3]
    cache_path = Path(args.cache_dir)
    if not cache_path.is_absolute():
        cache_path = root / cache_path

    cache = EmbeddingCache(cache_path)
    config = QwenExtractorConfig(
        model_name=args.model,
        layer_idx=args.layer,
        chunk_policy=args.chunk_policy,
        mock=args.mock,
    )
    pipeline = QwenEmbeddingPipeline(config)

    # Resolve case directories
    if args.case == "synthetic":
        case_dir = root / "tests" / "fixtures" / "synthetic"
        parquet_dir = case_dir / "parquet"
        source_file = case_dir / "synthetic_target.c"
        src_text = source_file.read_text(encoding="utf-8")
        function_sources = {
            "aux_counter": src_text,
            "process_and_fault": src_text,
            "main": src_text,
        }
    else:
        case_dir = root / "cases" / args.case
        parquet_dir = case_dir / "parquet"
        function_sources = {}
        nodes_file = parquet_dir / "nodes.parquet"
        if nodes_file.exists():
            nodes_df = pd.read_parquet(nodes_file)
            for _, row in nodes_df.iterrows():
                func_id = row["function_id"]
                spans_raw = json.loads(row["source_spans"])
                if spans_raw and func_id not in function_sources:
                    raw_file = spans_raw[0]["file"]
                    fname = Path(raw_file).name
                    candidate_paths = [
                        case_dir / "src" / fname,
                        Path(raw_file),
                        root / raw_file.lstrip("/"),
                        root / raw_file.replace("/workspace/", "").lstrip("/"),
                        root / "build_test" / raw_file.replace("/build/", "").lstrip("/"),
                        root / "build_test" / raw_file.replace("/workspace/build_test/", "").lstrip("/"),
                        root.parent / raw_file.replace("/workspace/nycu-dissertation/", "").lstrip("/"),
                        root.parent / "bench" / "target" / "benchmark-project" / raw_file.lstrip("/"),
                        case_dir / fname,
                    ]
                    for cp in candidate_paths:
                        if cp.exists() and cp.is_file():
                            try:
                                function_sources[func_id] = cp.read_text(encoding="utf-8", errors="replace")
                                break
                            except Exception:
                                pass

    nodes_file = parquet_dir / "nodes.parquet"
    if not nodes_file.exists():
        raise FileNotFoundError(f"nodes.parquet not found in {parquet_dir}")

    nodes_df = pd.read_parquet(nodes_file)
    bb_source_spans = {}
    bb_to_function = {}

    for _, row in nodes_df.iterrows():
        bb_id = row["bb_id"]
        func_id = row["function_id"]
        bb_to_function[bb_id] = func_id
        spans_raw = json.loads(row["source_spans"])
        bb_source_spans[bb_id] = [SourceSpan(**s) for s in spans_raw]

    embs, missing = pipeline.extract_and_cache_case(
        case_id=args.case,
        bb_source_spans=bb_source_spans,
        function_sources=function_sources,
        bb_to_function=bb_to_function,
        cache=cache,
        force_recompute=True,
    )

    num_total = len(embs)
    num_missing = sum(1 for m in missing.values() if m)
    print(f"Extraction complete for {args.case}: {num_total} BBs processed, {num_missing} zero-masked.")


if __name__ == "__main__":
    main()


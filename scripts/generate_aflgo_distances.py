#!/usr/bin/env python3
"""Compute AFLGo CFG-scoped model line scores and generate adapted distance files.

Implements dissertation linescore experiment plan:
1. Identifies reachable basic blocks from AFLGo physical distance (finite d_phys).
2. Maps blocks to exact source lines via block_mapping.jsonl.
3. Extracts candidate functions from bench/src/ using Tree-sitter.
4. Performs ModernBERT inference:
   - Incoming attention: pipeline_20261012_231316/modernbert_classification/best.pt
   - CLS attention: pipeline_20261012_231316/modernbert_rationale/best.pt
5. Applies Eq. 7-9 normalization, 90th percentile capping, and distance adjustment.
6. Directly outputs to the benchmark directory:
   - distance.physical.cfg.txt
   - distance.attention.cfg.txt
   - distance.rationale.cfg.txt
   - provenance.json
"""

import argparse
import hashlib
import json
import math
import os
import shutil
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "attention"), str(ROOT / "neuron"), str(ROOT / "aflgo/scripts")]

import numpy as np
import torch
from transformers import AutoTokenizer

from core.mapper import prepare_code_input
from model import line_distribution, load_model
from prepare_aflgo_distance import (
    load_block_mapping,
    load_physical_distances,
    normalize_path,
    process_model_distance,
)
from rescore_checkpoint import IncomingCollector
from score_bench import function_name, valid_function_boundary

BENCH_DIR = ROOT / "bench"
BENCH_SRC_DIR = BENCH_DIR / "src"
SOURCES_JSON = BENCH_SRC_DIR / "sources.json"

DEFAULT_CLS_RUN = ROOT / "attention/outputs/pipeline_20261012_231316/modernbert_classification"
DEFAULT_RAT_RUN = ROOT / "attention/outputs/pipeline_20261012_231316/modernbert_rationale"


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_sources_map():
    if not SOURCES_JSON.is_file():
        raise FileNotFoundError(f"Missing {SOURCES_JSON}")
    with open(SOURCES_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    project_to_src = {}
    for entry in data:
        key = entry["key"]
        roots = entry.get("roots", [])
        for proj in entry.get("projects", []):
            if roots:
                folder_name = Path(roots[0]).name
                src_path = BENCH_SRC_DIR / key / folder_name
            else:
                src_path = BENCH_SRC_DIR / key
            project_to_src[proj] = (src_path, key)
    return project_to_src


def scan_source_functions(source_files, source_root):
    """Scan source files with Tree-sitter to locate all valid function definitions."""
    from tree_sitter import Language, Parser
    import tree_sitter_c
    import tree_sitter_cpp

    parsers = {
        "c": Parser(Language(tree_sitter_c.language())),
        "cpp": Parser(Language(tree_sitter_cpp.language())),
    }
    for p in parsers.values():
        p.timeout_micros = 2_000_000

    functions = []
    file_status = []

    for path in sorted(source_files):
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in (
            ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"
        ):
            continue

        data = path.read_bytes()
        try:
            rel = path.relative_to(source_root).as_posix()
        except ValueError:
            rel = path.name

        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            file_status.append(dict(file=rel, status="non_utf8", functions=0))
            continue

        parser = parsers["c" if path.suffix.lower() in (".c", ".h") else "cpp"]
        try:
            tree = parser.parse(data)
        except ValueError:
            parser.reset()
            file_status.append(dict(file=rel, status="parse_timeout", functions=0))
            continue

        stack = [tree.root_node]
        count = 0
        while stack:
            node = stack.pop()
            if node.type != "function_definition":
                stack.extend(reversed(node.named_children))
                continue

            name = function_name(node, data)
            start, end = node.start_point.row, node.end_point.row
            code = " " * node.start_point.column + data[node.start_byte:node.end_byte].decode("utf-8")
            fid = hashlib.sha256(code.encode("utf-8")).hexdigest()
            boundary_ok = bool(name) and (not node.has_error or valid_function_boundary(node, data))

            functions.append(
                dict(
                    file=rel,
                    abs_path=str(path.resolve()),
                    name=name or "",
                    start=start + 1,
                    end=end + 1,
                    status="ok" if boundary_ok else "parse_error",
                    code=code,
                    code_sha256=fid,
                )
            )
            count += 1

        file_status.append(
            dict(file=rel, status="file_has_parse_errors" if tree.root_node.has_error else "ok", functions=count)
        )

    return functions, file_status


def score_functions_with_models(candidates_by_fid, classification_dir, rationale_dir, device="cpu", cpu_threads=4):
    """Run ModernBERT inference for both incoming attention and CLS rationale."""
    torch.set_num_threads(cpu_threads)

    models_info = [
        ("attention_distance", classification_dir, "classification"),
        ("rationale", rationale_dir, "rationale"),
    ]

    all_scores = {}

    for method, run_dir, mode_desc in models_info:
        run_json_path = run_dir / "run.json"
        best_pt_path = run_dir / "best.pt"

        if not run_json_path.is_file() or not best_pt_path.is_file():
            raise FileNotFoundError(f"Missing run.json or best.pt in {run_dir}")

        info = json.loads(run_json_path.read_text(encoding="utf-8"))
        max_length = info["arguments"].get("max_length", 8192)
        model_id = info["model_id"]
        revision = info["revision"]

        print(f"[{method}] Loading {model_id} (revision {revision[:8]})...")
        tokenizer = AutoTokenizer.from_pretrained(model_id, revision=revision, use_fast=True)
        model = load_model(info["arguments"]["model"], revision)

        checkpoint = torch.load(best_pt_path, map_location="cpu", weights_only=True)
        model.load_state_dict(checkpoint["state_dict"], strict=True)
        del checkpoint

        model.to(device).eval()

        collector = IncomingCollector(model.encoder, chunk_size=128) if method == "attention_distance" else None
        method_results = {}

        try:
            for fid, code in candidates_by_fid.items():
                tokens_count = len(tokenizer(code, truncation=False, verbose=False)["input_ids"])
                if tokens_count > max_length:
                    method_results[fid] = dict(status="overlength", tokens=tokens_count)
                    continue

                inputs, mapping, valid, truncated = prepare_code_input(code, tokenizer, max_length)
                if truncated:
                    method_results[fid] = dict(status="truncated", tokens=tokens_count)
                    continue

                if collector:
                    collector.clear()

                with torch.inference_mode():
                    logits, att = model({k: v.to(device) for k, v in inputs.items()})

                order = sorted(valid)
                if collector:
                    if collector.count != collector.expected:
                        raise ValueError(f"Incomplete attention capture: {collector.count} != {collector.expected}")
                    raw = np.zeros(len(order))
                    compact = {q: j for j, q in enumerate(order)}
                    for t, q in mapping.items():
                        if q in compact:
                            raw[compact[q]] += float(collector.total[t])
                    raw_sum = raw.sum()
                    values = raw / (raw_sum if raw_sum > 0 else 1.0)
                else:
                    compact = {q: j for j, q in enumerate(order)}
                    ids = torch.tensor([compact.get(mapping[t], -1) for t in range(len(mapping))], device=device)
                    values = line_distribution(att[0], ids).cpu().numpy()
                    raw = values

                if not np.isfinite(values).all():
                    raise ValueError(f"Non-finite scores for function {fid}")

                prob = float(logits.softmax(-1)[0, 1]) if logits.shape[-1] > 1 else float(logits[0, 0])
                method_results[fid] = dict(
                    status="scored",
                    tokens=tokens_count,
                    lines=order,
                    scores=values.tolist(),
                    raw_scores=raw.tolist(),
                    function_probability=prob,
                )
        finally:
            if collector:
                collector.close()
            del model
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

        all_scores[method] = (method_results, info, digest_file(best_pt_path))

    return all_scores


def generate_distances_for_benchmark(
    bench_name: str,
    classification_dir: Path = DEFAULT_CLS_RUN,
    rationale_dir: Path = DEFAULT_RAT_RUN,
    device: str = "cpu",
    cpu_threads: int = 4,
    skip_existing: bool = False,
):
    bench_dir = BENCH_DIR / bench_name
    if not bench_dir.is_dir():
        raise FileNotFoundError(f"Benchmark directory not found: {bench_dir}")

    if skip_existing:
        att_file = bench_dir / "distance.attention.cfg.txt"
        rat_file = bench_dir / "distance.rationale.cfg.txt"
        if att_file.is_file() and att_file.stat().st_size > 0 and rat_file.is_file() and rat_file.stat().st_size > 0:
            print(f"[{bench_name}] Model distances already exist, skipping (--skip-existing)")
            return

    # Locate AFLGo Stage 1 distance.physical.cfg.txt and block_mapping.jsonl
    phys_file = bench_dir / "distance.physical.cfg.txt"
    if not phys_file.is_file():
        phys_file = bench_dir / "distance.cfg.txt"
    if not phys_file.is_file():
        raise FileNotFoundError(
            f"Physical distance file not found in {bench_dir}. Run scripts/extract_aflgo_cfg.py first!"
        )

    bm_file = bench_dir / "block_mapping.jsonl"
    if not bm_file.is_file():
        raise FileNotFoundError(
            f"block_mapping.jsonl not found in {bench_dir}. Run scripts/extract_aflgo_cfg.py first!"
        )

    # 1. Load physical distances (finite reachability scope)
    phys_distances = load_physical_distances(phys_file)
    print(f"[{bench_name}] Total physical distance blocks: {len(phys_distances)}")

    # 2. Load block mapping and filter to reachable blocks
    raw_blocks = load_block_mapping(bm_file)
    reachable_blocks = [b for b in raw_blocks if b.get("distance_key") in phys_distances]
    print(f"[{bench_name}] Reachable basic block entries in mapping: {len(reachable_blocks)}")

    blocks_by_key = defaultdict(list)
    needed_lines_by_file = defaultdict(set)
    for b in reachable_blocks:
        k = b.get("distance_key")
        blocks_by_key[k].append(b)
        for sl in b.get("source_lines", []):
            fn = normalize_path(sl.get("file", ""))
            ln = int(sl.get("line", 0))
            if ln > 0:
                needed_lines_by_file[fn].add(ln)
                needed_lines_by_file[Path(fn).name].add(ln)

    # 3. Locate source files in bench/src
    sources_map = load_sources_map()
    if bench_name not in sources_map:
        raise KeyError(f"Benchmark {bench_name} not found in sources.json")
    src_root, source_key = sources_map[bench_name]
    print(f"[{bench_name}] Source root: {src_root} (key: {source_key})")

    # Match files needed
    candidate_source_paths = set()
    needed_basenames = {Path(fn).name for fn in needed_lines_by_file}
    for p in src_root.rglob("*"):
        if p.is_file() and p.name in needed_basenames:
            candidate_source_paths.add(p)

    print(f"[{bench_name}] Found {len(candidate_source_paths)} source files matching reachable blocks")

    # 4. Scan functions with Tree-sitter
    functions, file_status = scan_source_functions(candidate_source_paths, src_root)
    print(f"[{bench_name}] Scanned {len(functions)} total functions in matching files")

    # Filter to functions that cover at least one reachable line
    selected_functions = []
    for f in functions:
        fname = normalize_path(f["file"])
        fbase = Path(fname).name
        target_lines = needed_lines_by_file.get(fname, set()) | needed_lines_by_file.get(fbase, set())
        if any(f["start"] <= ln <= f["end"] for ln in target_lines):
            selected_functions.append(f)

    print(f"[{bench_name}] Selected {len(selected_functions)} functions covering CFG reachable basic blocks")
    if not selected_functions:
        raise RuntimeError(f"[{bench_name}] Zero functions matched reachable CFG blocks!")

    candidates_by_fid = {f["code_sha256"]: f["code"] for f in selected_functions if f["status"] == "ok"}
    print(f"[{bench_name}] {len(candidates_by_fid)} candidate functions ready for model scoring")

    # 5. Run model scoring
    all_scores = score_functions_with_models(
        candidates_by_fid,
        classification_dir,
        rationale_dir,
        device=device,
        cpu_threads=cpu_threads,
    )

    # 6. Map scores to lines
    method_line_scores = {}
    method_records = {}

    for method_key, (results, model_info, ckpt_sha) in all_scores.items():
        label = "attention" if method_key == "attention_distance" else "rationale"
        line_score_map = {}
        records = []

        for func in selected_functions:
            res = results.get(func["code_sha256"])
            if not res or res.get("status") != "scored":
                continue

            for offset, val in zip(res["lines"], res["scores"]):
                actual_line = func["start"] + offset
                f_rel = normalize_path(func["file"])
                f_base = Path(f_rel).name

                line_score_map[(f_rel, actual_line)] = val
                line_score_map[(f_base, actual_line)] = val

                records.append(
                    dict(
                        method=label,
                        file=f_rel,
                        line=actual_line,
                        score=float(val),
                        function=func["name"],
                        code_sha256=func["code_sha256"],
                        status="scored",
                        checkpoint_sha256=ckpt_sha,
                    )
                )

        method_line_scores[label] = line_score_map
        method_records[label] = records
        print(f"[{bench_name}] [{label}] Scored {len(records)} lines across {len(selected_functions)} functions")

    # 7. Compute adapted distances via Eq. 7-9
    d_att, w_att, stats_att = process_model_distance(
        "attention", method_line_scores["attention"], blocks_by_key, phys_distances
    )
    d_rat, w_rat, stats_rat = process_model_distance(
        "rationale", method_line_scores["rationale"], blocks_by_key, phys_distances
    )

    print(f"[{bench_name}] [Attention] Coverage: {stats_att['coverage_ratio']:.2%}, "
          f"Scored: {stats_att['scored_blocks']}/{stats_att['total_phys_blocks']}")
    print(f"[{bench_name}] [Rationale] Coverage: {stats_rat['coverage_ratio']:.2%}, "
          f"Scored: {stats_rat['scored_blocks']}/{stats_rat['total_phys_blocks']}")

    # 8. Output files to benchmark directory
    # 8.1 distance.physical.cfg.txt
    dest_phys = bench_dir / "distance.physical.cfg.txt"
    with open(dest_phys, "w", encoding="utf-8") as f:
        for k, d in sorted(phys_distances.items()):
            f.write(f"{k},{d:.12f}\n")

    # 8.2 distance.attention.cfg.txt
    dest_att = bench_dir / "distance.attention.cfg.txt"
    with open(dest_att, "w", encoding="utf-8") as f:
        for k, d in sorted(d_att.items()):
            f.write(f"{k},{d:.12f}\n")

    # 8.3 distance.rationale.cfg.txt
    dest_rat = bench_dir / "distance.rationale.cfg.txt"
    with open(dest_rat, "w", encoding="utf-8") as f:
        for k, d in sorted(d_rat.items()):
            f.write(f"{k},{d:.12f}\n")

    # 8.4 Save provenance metadata directly in benchmark directory
    provenance = {
        "benchmark": bench_name,
        "source_key": source_key,
        "source_root": str(src_root),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_phys_blocks": len(phys_distances),
        "models": {
            "attention": {
                "checkpoint": str(classification_dir / "best.pt"),
                "checkpoint_sha256": all_scores["attention_distance"][2],
                "stats": stats_att,
            },
            "rationale": {
                "checkpoint": str(rationale_dir / "best.pt"),
                "checkpoint_sha256": all_scores["rationale"][2],
                "stats": stats_rat,
            },
        },
        "outputs": {
            "distance.physical.cfg.txt": digest_file(dest_phys),
            "distance.attention.cfg.txt": digest_file(dest_att),
            "distance.rationale.cfg.txt": digest_file(dest_rat),
        },
        "status": "complete",
    }

    prov_path = bench_dir / "provenance.json"
    with open(prov_path, "w", encoding="utf-8") as f:
        json.dump(provenance, f, indent=2)

    print(f"\n[{bench_name}] Distance generation successful!")
    print(f"  -> {dest_phys}")
    print(f"  -> {dest_att}")
    print(f"  -> {dest_rat}")
    print(f"  -> Provenance saved to {prov_path}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Generate AFLGo distance files with ModernBERT incoming attention and CLS rationale."
    )
    parser.add_argument(
        "benchmark",
        nargs="?",
        default="binutils-2.26_cxxfilt_CVE-2016-4487",
        help="Benchmark name (default: binutils-2.26_cxxfilt_CVE-2016-4487)",
    )
    parser.add_argument(
        "--classification-run",
        type=Path,
        default=DEFAULT_CLS_RUN,
        help="Path to modernbert_classification directory",
    )
    parser.add_argument(
        "--rationale-run",
        type=Path,
        default=DEFAULT_RAT_RUN,
        help="Path to modernbert_rationale directory",
    )
    parser.add_argument(
        "--device",
        choices=["cpu", "cuda"],
        default="cuda" if torch.cuda.is_available() else "cpu",
        help="Compute device (default: cuda if available, else cpu)",
    )
    parser.add_argument(
        "--cpu-threads",
        type=int,
        default=4,
        help="Number of CPU threads for PyTorch",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Generate distances for all benchmarks in sources.json",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip benchmarks that already have valid attention and rationale distance files",
    )

    args = parser.parse_args()

    if args.all:
        sources_map = load_sources_map()
        for b in sorted(sources_map.keys()):
            try:
                generate_distances_for_benchmark(
                    b,
                    classification_dir=args.classification_run,
                    rationale_dir=args.rationale_run,
                    device=args.device,
                    cpu_threads=args.cpu_threads,
                    skip_existing=args.skip_existing,
                )
            except Exception as e:
                print(f"[{b}] Failed: {e}", file=sys.stderr)
    else:
        generate_distances_for_benchmark(
            args.benchmark,
            classification_dir=args.classification_run,
            rationale_dir=args.rationale_run,
            device=args.device,
            cpu_threads=args.cpu_threads,
            skip_existing=args.skip_existing,
        )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Export raw line scores from attention/outputs/bench_scores for AFLGo distance adaptation.

Follows the dissertation Linescore experiment plan (bench/linescore/README.md §3, Stage D):
- Reads models.json, mapping.json, catalog.json, and scores.sqlite.
- Extracts line scores directly from model inference results without DAFL percentile scaling.
- Generates line_scores.attention.jsonl, line_scores.rationale.jsonl, and provenance.json.
"""

import argparse
import json
import math
import os
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def export_scores_for_benchmark(bench_name, scores_dir, out_dir):
    scores_dir = Path(scores_dir).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    models_path = scores_dir / "models.json"
    mapping_path = scores_dir / "mapping.json"
    catalog_path = scores_dir / "catalog.json"
    sqlite_path = scores_dir / "scores.sqlite"

    for p in (models_path, mapping_path, catalog_path, sqlite_path):
        if not p.is_file():
            raise FileNotFoundError(f"Missing required file: {p}")

    models_data = load_json(models_path)
    mapping_data = load_json(mapping_path)
    catalog_data = load_json(catalog_path)

    if bench_name not in mapping_data:
        raise KeyError(f"Benchmark '{bench_name}' not found in mapping.json")

    bench_mapping = mapping_data[bench_name]
    source_key = bench_mapping.get("source_key")
    if not source_key or source_key not in catalog_data:
        raise KeyError(f"Source key '{source_key}' for '{bench_name}' not found in catalog.json")

    catalog_entry = catalog_data[source_key]
    functions_list = catalog_entry.get("functions", [])
    source_root = catalog_entry.get("root", "")

    # Index functions by code_sha256
    funcs_by_sha = {f["code_sha256"]: f for f in functions_list if "code_sha256" in f}
    print(f"[{bench_name}] Catalog source_key: {source_key}, total functions: {len(funcs_by_sha)}")

    conn = sqlite3.connect(sqlite_path)
    cursor = conn.cursor()

    provenance = {
        "benchmark": bench_name,
        "source_key": source_key,
        "source_root": source_root,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "models": models_data.get("models", {}),
        "methods": {},
        "target_trace": bench_mapping.get("targets", [])
    }

    method_specs = [
        ("attention", models_data["keys"]["attention_distance"], "attention_distance"),
        ("rationale", models_data["keys"]["rationale"], "rationale"),
    ]

    for label, method_key, model_key_name in method_specs:
        model_meta = models_data.get("models", {}).get(model_key_name, {})
        checkpoint_sha = model_meta.get("checkpoint_sha256", "unknown")

        cursor.execute("SELECT code, result FROM scores WHERE method = ?", (method_key,))
        rows = cursor.fetchall()

        matched_scores = []
        line_score_map = {}  # (file, line) -> dict
        collisions = []

        functions_scored = 0
        total_lines_scored = 0

        for code_sha, result_str in rows:
            if code_sha not in funcs_by_sha:
                continue

            func_info = funcs_by_sha[code_sha]
            func_name = func_info.get("name", "")
            func_file = func_info.get("file", "")
            func_start = func_info.get("start", 1)

            try:
                result = json.loads(result_str)
            except Exception as e:
                continue

            status = result.get("status", "")
            if status != "scored":
                continue

            lines = result.get("lines", [])
            scores = result.get("scores", [])
            raw_scores = result.get("raw_scores", scores)

            functions_scored += 1

            for offset, score, raw in zip(lines, scores, raw_scores):
                if not math.isfinite(score) or score < 0:
                    continue

                abs_line = func_start + offset
                key = (func_file, abs_line)

                record = {
                    "method": label,
                    "file": func_file,
                    "line": abs_line,
                    "score": float(score),
                    "raw_score": float(raw) if math.isfinite(raw) else float(score),
                    "function": func_name,
                    "code_sha256": code_sha,
                    "checkpoint_sha256": checkpoint_sha,
                    "status": "scored"
                }

                if key in line_score_map:
                    collisions.append({
                        "file": func_file,
                        "line": abs_line,
                        "existing": line_score_map[key],
                        "new": record
                    })
                    # Conservative deterministic tie-break: take maximum score
                    if record["score"] > line_score_map[key]["score"]:
                        line_score_map[key] = record
                else:
                    line_score_map[key] = record

        # Sort entries by file, line
        sorted_records = sorted(line_score_map.values(), key=lambda r: (r["file"], r["line"]))
        out_file = out_dir / f"line_scores.{label}.jsonl"

        with open(out_file, "w", encoding="utf-8") as f:
            for rec in sorted_records:
                f.write(json.dumps(rec) + "\n")

        print(f"[{bench_name}] Exported {label}: {len(sorted_records)} line scores across {functions_scored} functions ({len(collisions)} collisions)")

        provenance["methods"][label] = {
            "method_key": method_key,
            "checkpoint_sha256": checkpoint_sha,
            "functions_scored": functions_scored,
            "lines_scored": len(sorted_records),
            "collisions_count": len(collisions),
            "output_file": str(out_file.name)
        }

    prov_file = out_dir / "provenance.json"
    with open(prov_file, "w", encoding="utf-8") as f:
        json.dump(provenance, f, indent=2)

    conn.close()
    print(f"[{bench_name}] Export completed -> {out_dir}")
    return out_dir


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("benchmark", help="Benchmark name (e.g. binutils-2.26_cxxfilt_CVE-2016-4487)")
    parser.add_argument("--scores-dir", default="attention/outputs/bench_scores", help="Path to bench_scores dir")
    parser.add_argument("--out-dir", default=None, help="Output directory")
    args = parser.parse_args()

    if args.out_dir is None:
        out_dir = Path("bench/linescore/outputs") / args.benchmark
    else:
        out_dir = Path(args.out_dir)

    export_scores_for_benchmark(args.benchmark, args.scores_dir, out_dir)


if __name__ == "__main__":
    main()

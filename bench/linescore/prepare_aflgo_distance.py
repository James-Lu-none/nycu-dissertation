#!/usr/bin/env python3
"""Transform AFLGo CFG physical distances with attention / rationale line scores.

Implements Eq. 7–9 of 2512.19758v1.pdf §3.3–3.4 and dissertation experiment plan
bench/linescore/README.md §3 Stage E:

1. w_orig(block) = sum(score(line)) for unique effective source lines in block
2. cap = value at ceil(0.1 * N) when scored block values are sorted descending
3. clipped(block) = min(w_orig(block), cap)
4. w_min = min(clipped), w_max = max(clipped)
5. w(block) = 0.5 if w_max == w_min else (clipped - w_min) / (w_max - w_min)
   (unscored / missing blocks default to neutral w=0.5 => d = d_phys)
6. d = d_phys * (1.5 - w)
"""

import argparse
import json
import math
from pathlib import Path


def normalize_path(path_str):
    if not path_str:
        return ""
    p = path_str.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p


def line_matches(file_a, line_a, file_b, line_b):
    if line_a != line_b:
        return False
    fa = normalize_path(file_a)
    fb = normalize_path(file_b)
    if fa == fb:
        return True
    if fa.endswith("/" + fb) or fb.endswith("/" + fa):
        return True
    # Basename match
    return Path(fa).name == Path(fb).name


def load_line_scores(score_file):
    scores = {}
    with open(score_file, encoding="utf-8") as stream:
        for text in stream:
            if not text.strip():
                continue
            rec = json.loads(text)
            key = (normalize_path(rec["file"]), int(rec["line"]))
            value = float(rec["score"])
            if key[1] < 1 or not math.isfinite(value) or value < 0:
                raise ValueError(f"Invalid line score: {rec}")
            if key in scores:
                raise ValueError(f"Duplicate line score: {key}")
            scores[key] = value
    return scores, list(scores.values())


def load_block_mapping(block_mapping_file):
    blocks = []
    with open(block_mapping_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            blocks.append(rec)
    return blocks


def load_physical_distances(distance_file):
    distances = {}
    with open(distance_file, encoding="utf-8") as stream:
        for text in stream:
            if not text.strip():
                continue
            key, value = text.strip().split(",")
            key = key.strip()
            value = float(value)
            if not key or key in distances or not math.isfinite(value) or value < 0:
                raise ValueError(f"Invalid or duplicate physical distance: {text.strip()}")
            distances[key] = value
    return distances


def block_lines(entries):
    return {(normalize_path(s["file"]), int(s["line"]))
            for entry in entries for s in entry.get("source_lines", []) if int(s["line"]) > 0}


def process_model_distance(model_name, scores_by_line, blocks_by_key, phys_distances, common_keys=None):
    """Compute Eq. 7-9 for a given model."""
    block_raw_w = {}
    scored_keys = set()
    missing_keys = set()

    for key, d_phys in phys_distances.items():
        if key not in blocks_by_key:
            # Fallback if key missing in mapping: neutral
            missing_keys.add(key)
            block_raw_w[key] = 0.0
            continue

        unique_lines = block_lines(blocks_by_key[key])
        complete = bool(unique_lines) and unique_lines <= scores_by_line.keys()
        if complete and (common_keys is None or key in common_keys):
            block_raw_w[key] = sum(scores_by_line[line] for line in sorted(unique_lines))
            scored_keys.add(key)
        else:
            block_raw_w[key] = 0.0
            missing_keys.add(key)

    if not scored_keys:
        raise RuntimeError(f"[{model_name}] Zero blocks matched model line scores! Cannot apply adaptation.")

    # 90th percentile capping on scored blocks
    scored_values = sorted([block_raw_w[k] for k in scored_keys], reverse=True)
    N = len(scored_values)
    cap_idx = max(0, math.ceil(0.1 * N) - 1)
    cap_value = scored_values[cap_idx]

    clipped = {}
    for k in scored_keys:
        clipped[k] = min(block_raw_w[k], cap_value)

    w_min = min(clipped.values())
    w_max = max(clipped.values())

    normalized_w = {}
    for k, d_phys in phys_distances.items():
        if k in scored_keys:
            if w_max == w_min:
                w = 0.5
            else:
                w = (clipped[k] - w_min) / (w_max - w_min)
        else:
            # Neutral default for unmodeled / missing blocks: w = 0.5 => factor = 1.0
            w = 0.5
        normalized_w[k] = w

    # Calculate final distances: d = d_phys * (1.5 - w)
    final_distances = {}
    for k, d_phys in phys_distances.items():
        if d_phys == 0.0:
            # Target block remains 0
            d_final = 0.0
        else:
            w = normalized_w[k]
            factor = 1.5 - w
            d_final = d_phys * factor
        final_distances[k] = d_final

    stats = {
        "model": model_name,
        "raw_block_scores": block_raw_w,
        "scored_keys": sorted(scored_keys),
        "total_phys_blocks": len(phys_distances),
        "scored_blocks": len(scored_keys),
        "missing_blocks": len(missing_keys),
        "coverage_ratio": len(scored_keys) / len(phys_distances) if phys_distances else 0.0,
        "cap_value": cap_value,
        "w_min": w_min,
        "w_max": w_max,
        "factor_range": [float(min(1.5 - w for w in normalized_w.values())), float(max(1.5 - w for w in normalized_w.values()))],
        "d_phys_range": [float(min(phys_distances.values())), float(max(phys_distances.values()))],
        "d_final_range": [float(min(final_distances.values())), float(max(final_distances.values()))]
    }

    return final_distances, normalized_w, stats


def prepare_aflgo_distances(phys_distance_file, block_mapping_file, attention_scores_file, rationale_scores_file, out_dir):
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    phys_distances = load_physical_distances(phys_distance_file)
    if not phys_distances:
        raise ValueError(f"Physical distance file {phys_distance_file} is empty or invalid!")

    raw_blocks = [json.loads(s) for s in sorted({json.dumps(b, sort_keys=True) for b in load_block_mapping(block_mapping_file)})]
    blocks_by_key = {}
    for b in raw_blocks:
        dk = b.get("distance_key", "")
        if not dk:
            bid = b.get("block_id", "")
            dk = bid.rstrip(":")
        if dk:
            blocks_by_key.setdefault(dk, []).append(b)

    att_scores, _ = load_line_scores(attention_scores_file)
    rat_scores, _ = load_line_scores(rationale_scores_file)

    common = {key for key in phys_distances
              if block_lines(blocks_by_key.get(key, []))
              and block_lines(blocks_by_key[key]) <= att_scores.keys()
              and block_lines(blocks_by_key[key]) <= rat_scores.keys()}
    att_dists, att_w, att_stats = process_model_distance("attention", att_scores, blocks_by_key, phys_distances, common)
    rat_dists, rat_w, rat_stats = process_model_distance("rationale", rat_scores, blocks_by_key, phys_distances, common)
    if att_dists == phys_distances or rat_dists == phys_distances or att_dists == rat_dists:
        raise ValueError("Degenerate model distances: no distinct three-group comparison")
    with (out_dir / "block_scores.jsonl").open("w", encoding="utf-8") as stream:
        for key in sorted(phys_distances):
            record = dict(distance_key=key, physical=phys_distances[key], common_scored=key in common,
                          mapping_entries=len(blocks_by_key.get(key, [])))
            for name, weights, distances, stats in [("attention", att_w, att_dists, att_stats), ("rationale", rat_w, rat_dists, rat_stats)]:
                record[name] = dict(raw=stats["raw_block_scores"][key], cap=stats["cap_value"],
                                    normalized=weights[key], distance=distances[key])
            stream.write(json.dumps(record) + "\n")

    # Write output files
    phys_out = out_dir / "distance.physical.cfg.txt"
    att_out = out_dir / "distance.attention.cfg.txt"
    rat_out = out_dir / "distance.rationale.cfg.txt"

    # Keep exactly the same key ordering
    sorted_keys = sorted(phys_distances.keys())

    with open(phys_out, "w", encoding="utf-8") as f:
        for k in sorted_keys:
            f.write(f"{k},{phys_distances[k]:.17g}\n")

    with open(att_out, "w", encoding="utf-8") as f:
        for k in sorted_keys:
            f.write(f"{k},{att_dists[k]:.17g}\n")

    with open(rat_out, "w", encoding="utf-8") as f:
        for k in sorted_keys:
            f.write(f"{k},{rat_dists[k]:.17g}\n")

    manifest = {
        "num_blocks": len(sorted_keys),
        "missing_policy": "shared complete-line mask; neutral otherwise",
        "key_merge_policy": "union of unique source lines across mapping entries sharing upstream key",
        "key_collisions": {k:len(v) for k,v in blocks_by_key.items() if len(v)>1},
        "physical_distance_file": str(phys_distance_file),
        "block_mapping_file": str(block_mapping_file),
        "outputs": {
            "physical": str(phys_out.name),
            "attention": str(att_out.name),
            "rationale": str(rat_out.name)
        },
        "statistics": {
            "attention": att_stats,
            "rationale": rat_stats
        }
    }

    manifest_file = out_dir / "distance_manifest.json"
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"Distances successfully generated in {out_dir}:")
    print(f"  - Physical : {phys_out.name} ({len(sorted_keys)} entries)")
    print(f"  - Attention: {att_out.name} (scored {att_stats['scored_blocks']}/{att_stats['total_phys_blocks']} blocks, cap={att_stats['cap_value']:.4f})")
    print(f"  - Rationale: {rat_out.name} (scored {rat_stats['scored_blocks']}/{rat_stats['total_phys_blocks']} blocks, cap={rat_stats['cap_value']:.4f})")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distance-phys", required=True, help="Input distance.physical.cfg.txt from gen_distance_fast.py")
    parser.add_argument("--block-mapping", required=True, help="Input block_mapping.jsonl from Stage 1 AFLGo pass")
    parser.add_argument("--attention-scores", required=True, help="Input line_scores.attention.jsonl from export_aflgo_scores.py")
    parser.add_argument("--rationale-scores", required=True, help="Input line_scores.rationale.jsonl from export_aflgo_scores.py")
    parser.add_argument("--out-dir", required=True, help="Output directory for generated distance files")
    args = parser.parse_args()

    prepare_aflgo_distances(
        args.distance_phys,
        args.block_mapping,
        args.attention_scores,
        args.rationale_scores,
        args.out_dir
    )


if __name__ == "__main__":
    main()

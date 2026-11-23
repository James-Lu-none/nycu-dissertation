"""Fail-closed conversion of DG survivor metadata into exploratory slice masks.

Never interpret membership in a static slice as a vulnerability ground truth.
The DG slicer and target_graph's original LLVM identity pass are deliberately
separate: this module verifies their alignment before exporting any IDs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def _records(path: Path) -> dict[str, dict]:
    if not path.is_file():
        raise ValueError(f"Required identity file does not exist: {path}")
    rows: dict[str, dict] = {}
    with path.open(encoding="utf-8") as stream:
        for line_no, text in enumerate(stream, 1):
            if not text.strip():
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected object")
            identity = row.get("id")
            bb_id = row.get("bb_id")
            if not isinstance(identity, str) or not identity:
                raise ValueError(f"{path}:{line_no}: missing instruction ID")
            if not isinstance(bb_id, str) or not bb_id:
                raise ValueError(f"{path}:{line_no}: missing BB ID")
            if identity.rsplit(":", 1)[0] != bb_id:
                raise ValueError(f"{path}:{line_no}: inconsistent BB identity")
            if identity in rows:
                raise ValueError(f"{path}:{line_no}: duplicate instruction ID {identity}")
            rows[identity] = row
    return rows


def _legacy_bbs(path: Path) -> set[str]:
    blocks: set[str] = set()
    with path.open(encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            bb_id = row.get("bb_id")
            if not isinstance(bb_id, str) or not bb_id:
                raise ValueError(f"{path}:{line_no}: invalid BB ID")
            if bb_id in blocks:
                raise ValueError(f"{path}:{line_no}: duplicate BB ID")
            blocks.add(bb_id)
    return blocks


def _v2_instructions(path: Path) -> set[str]:
    ids: set[str] = set()
    with path.open(encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("kind") == "instruction":
                identifier = row.get("id")
                if not isinstance(identifier, str) or identifier in ids:
                    raise ValueError(f"{path}:{line_no}: invalid or duplicate instruction")
                ids.add(identifier)
    return ids


def validate_survivors(
    before: Path,
    after: Path,
    target_inst: str,
    *,
    bb_map: Path | None = None,
    v2_nodes: Path | None = None,
    criterion: str = "",
    criterion_mode: str = "c",
    source_bc: Path | None = None,
    dg_commit: str = "dc3615d03fedfce62f37604b45d22e31c9d7e557",
) -> dict:
    if criterion_mode not in {"c", "sc"} or not criterion:
        raise ValueError("Explicit DG criterion and mode c/sc are required")
    original, surviving = _records(before), _records(after)
    if not original:
        raise ValueError("Pre-slice bitcode contained no tagged instructions")
    if target_inst not in original:
        raise ValueError(
            "Selected target instruction was not tagged in the original bitcode"
        )
    if not surviving:
        raise ValueError("DG returned no surviving tagged instructions")
    if target_inst not in surviving:
        raise ValueError(
            "DG output did not retain the selected target instruction; "
            "criterion mismatch or unsound identity mapping"
        )
    added = set(surviving) - set(original)
    if added:
        raise ValueError(
            f"DG output contains {len(added)} unknown original instruction IDs"
        )
    if bb_map is not None:
        mapped_bbs = _legacy_bbs(bb_map)
        missing = {row["bb_id"] for row in original.values()} - mapped_bbs
        if missing:
            raise ValueError(
                f"Original bitcode does not match bb_map.jsonl: {len(missing)} "
                "BB identities missing"
            )
    if v2_nodes is not None:
        v2_ids = _v2_instructions(v2_nodes)
        if set(original) != v2_ids:
            raise ValueError(
                "Original LLVM instructions do not match analysis_v2_nodes.jsonl; "
                "rebuild both analyses from exactly the same bitcode"
            )
    sha256 = None
    if source_bc is not None:
        if not source_bc.is_file():
            raise ValueError(f"Missing original bitcode: {source_bc}")
        digest = hashlib.sha256()
        with source_bc.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        sha256 = digest.hexdigest()
    return {
        "schema_version": 1,
        "backend": "DG/llvm-slicer",
        "dg_commit": dg_commit,
        "status": "EXPLORATORY_ONLY",
        "validated_for_supervision": False,
        "criterion_verified": False,
        "criterion_warning": (
            "Retaining target-inst in sliced bitcode does not prove DG's "
            "possibly approximate -c/-sc criterion selected that exact "
            "instruction or that the PoC executed it"
        ),
        "target": target_inst,
        "criterion": {"mode": criterion_mode, "value": criterion},
        "original_bitcode_sha256": sha256,
        "original_instruction_count": len(original),
        "surviving_instruction_count": len(surviving),
        "removed_instruction_count": len(original) - len(surviving),
        "instruction_ids": sorted(surviving),
        "basic_blocks": sorted({r["bb_id"] for r in surviving.values()}),
        "original_basic_block_count": len({r["bb_id"] for r in original.values()}),
        "identity_mapping": "llvm_instruction_metadata",
        "note": (
            "Surviving instructions indicate what DG retained, not an exact "
            "DDG/CDG witness or a verified vulnerability-causing trace. "
            "Newly created untagged DG instructions are intentionally ignored."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--target-inst", required=True)
    parser.add_argument("--criterion", required=True)
    parser.add_argument("--criterion-mode", choices=("c", "sc"), default="c")
    parser.add_argument("--bb-map", type=Path)
    parser.add_argument("--v2-nodes", type=Path)
    parser.add_argument("--source-bc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = validate_survivors(
        args.before, args.after, args.target_inst,
        bb_map=args.bb_map, v2_nodes=args.v2_nodes,
        criterion=args.criterion, criterion_mode=args.criterion_mode,
        source_bc=args.source_bc,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    staged = args.output.with_name(args.output.name + ".tmp")
    staged.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    os.replace(staged, args.output)
    print(
        f"[dg] {result['surviving_instruction_count']} original instructions in "
        f"{len(result['basic_blocks'])} original BBs; "
        "EXPLORATORY_ONLY (not training labels)"
    )


if __name__ == "__main__":
    main()

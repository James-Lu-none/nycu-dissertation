"""Parse direct canonical BB-ID execution traces."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional


def parse_trace_bb_ids(trace_file: Path) -> Optional[List[str]]:
    """Parse direct canonical BB IDs from trace file.

    Lines have format: "<seq>: <16-lowercase-hex-chars>" (no 0x prefix).
    Returns None if the trace file is missing or contains no valid BB IDs.
    """
    if not trace_file.exists():
        return None
    bb_ids: List[str] = []
    saw_legacy_pc = False
    expected_seq = 0
    with open(trace_file, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) != 2 or not parts[0].endswith(":"):
                raise ValueError(f"Malformed trace line: {stripped!r}")
            try:
                seq = int(parts[0][:-1])
            except ValueError as exc:
                raise ValueError(f"Invalid trace sequence: {stripped!r}") from exc
            if seq != expected_seq:
                raise ValueError(
                    f"Discontinuous trace sequence: expected {expected_seq}, got {seq}"
                )
            expected_seq += 1
            val = parts[1].lower()
            if val.startswith("0x"):
                saw_legacy_pc = True
                if bb_ids:
                    raise ValueError("Mixed direct BB IDs and legacy PCs in trace")
                continue
            if len(val) == 16 and all(c in "0123456789abcdef" for c in val):
                if saw_legacy_pc:
                    raise ValueError("Mixed legacy PCs and direct BB IDs in trace")
                bb_ids.append(val)
            else:
                raise ValueError(f"Malformed trace token: {val!r}")
    if saw_legacy_pc:
        return None
    return bb_ids if bb_ids else None


def trace_to_basic_blocks(trace_file: Path) -> List[str]:
    """Return ordered BB IDs from a direct trace file, collapsing consecutive duplicates."""
    direct_bbs = parse_trace_bb_ids(trace_file)
    if not direct_bbs:
        return []
    ordered_bbs: List[str] = []
    for bb in direct_bbs:
        if not ordered_bbs or ordered_bbs[-1] != bb:
            ordered_bbs.append(bb)
    return ordered_bbs

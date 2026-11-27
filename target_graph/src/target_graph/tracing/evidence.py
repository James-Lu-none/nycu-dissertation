"""Fail-closed artifact and ASan evidence checks for direct LLVM BB traces."""
from __future__ import annotations

import hashlib
import posixpath
import re
from pathlib import Path
from typing import Any

_ASAN = re.compile(r"(?:ERROR|SUMMARY):\s*AddressSanitizer:\s*([A-Za-z0-9_-]+)")
_FRAME = re.compile(r"^\s*#(\d+)\s+.*?\bin\s+(.+?)\s+(\S+?):(\d+)(?::\d+)?(?:\s|$)", re.M)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_source_path(value: str) -> str:
    """Lexically normalize ASan/DWARF POSIX paths, without basename fallback.

    Resolves /./ and /../ syntactically. Does not depend on container paths
    existing on the machine doing the audit (so no Path.resolve()).
    """
    normalized = posixpath.normpath(str(value).replace("\\", "/"))
    return "" if normalized == "." else normalized


def source_path_matches(frame_file: str, oracle_relative_source: str) -> bool:
    """Exact path-component suffix matching after lexical normalization."""
    if not oracle_relative_source:
        return False
    source = normalize_source_path(oracle_relative_source).strip("/")
    frame = normalize_source_path(frame_file)
    if not source or source == ".." or source.startswith("../"):
        return False
    return frame == source or frame.endswith("/" + source)


def asan_evidence(stderr: str, expected_oracle: dict[str, Any]) -> dict[str, Any]:
    """Report exact crash provenance; never infer it from BB coverage alone.

    A faulting frame match requires source filename/path suffix, exact line,
    and oracle function text. Matches to a non-top frame are separately flagged.
    """
    actual = (_ASAN.search(stderr).group(1) if _ASAN.search(stderr) else None)
    expected = expected_oracle.get("sanitizer")
    sanitizer_match = bool(actual and expected and
                           actual.casefold() == str(expected).casefold())
    source = normalize_source_path(str(expected_oracle.get("relative_source_file") or "")).strip("/")
    func = str(expected_oracle.get("function") or "").strip()
    try:
        line = int(expected_oracle.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    matched_frames = []
    all_frames = []
    for match in _FRAME.finditer(stderr):
        frame_no, frame_fn, frame_file, frame_line = match.groups()
        frame_file = normalize_source_path(frame_file)
        frame_num = int(frame_no)
        all_frames.append(frame_num)
        file_matches = source_path_matches(frame_file, source)
        if file_matches and line > 0 and int(frame_line) == line and (
            not func or func in frame_fn
        ):
            matched_frames.append(frame_num)
    return {
        "sanitizer_actual": actual,
        "sanitizer_expected": expected,
        "sanitizer_matches": sanitizer_match,
        "oracle_frame_matches": bool(matched_frames),
        "oracle_top_frame_matches": 0 in matched_frames,
        "oracle_frame_numbers": sorted(set(matched_frames)),
        "asan_frame_count": len(all_frames),
        "crash_reproduced": bool(sanitizer_match and matched_frames),
    }

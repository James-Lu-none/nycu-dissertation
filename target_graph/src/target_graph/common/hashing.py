"""Common hashing utilities ensuring deterministic and reproducible IDs."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Union


def hash_bytes(data: bytes) -> str:
    """Return SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_text(text: str) -> str:
    """Return SHA-256 hex digest of UTF-8 encoded text."""
    return hash_bytes(text.encode("utf-8"))


def hash_file(path: Union[str, Path]) -> str:
    """Compute SHA-256 of a file in 64KB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_bb_id(build_id: str, module: str, function: str, bb_ordinal: int) -> str:
    """Compute stable, build-local basic block ID.
    
    bb_id = hash(build_id, module, function, BB_ordinal)
    """
    key = f"{build_id}:{module}:{function}:{bb_ordinal}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


"""Embedding cache management and verification."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import torch


class EmbeddingCache:
    """Manages persistent disk caching of basic block embeddings with strict metadata validation."""

    def __init__(self, cache_dir: Path | str) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _case_dir(self, case_id: str) -> Path:
        p = self.cache_dir / case_id
        p.mkdir(parents=True, exist_ok=True)
        return p

    def get_paths(self, case_id: str, layer_idx: int) -> Tuple[Path, Path]:
        cdir = self._case_dir(case_id)
        emb_file = cdir / f"bb_embeddings_l{layer_idx}.pt"
        meta_file = cdir / f"metadata_l{layer_idx}.json"
        return emb_file, meta_file

    def has_valid_cache(
        self,
        case_id: str,
        layer_idx: int,
        expected_source_hash: Optional[str] = None,
        expected_model: str = "Qwen/Qwen2.5-Coder-7B",
        expected_dim: int = 3584,
    ) -> bool:
        emb_file, meta_file = self.get_paths(case_id, layer_idx)
        if not emb_file.exists() or not meta_file.exists():
            return False

        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            if meta.get("model") != expected_model:
                return False
            if meta.get("layer") != layer_idx:
                return False
            if meta.get("feature_dim") != expected_dim:
                return False
            if expected_source_hash and meta.get("source_hash") != expected_source_hash:
                return False
            return True
        except Exception:
            return False

    def save(
        self,
        case_id: str,
        layer_idx: int,
        bb_embeddings: Dict[str, torch.Tensor],
        missing_mask: Dict[str, bool],
        metadata: Dict[str, Any],
    ) -> None:
        emb_file, meta_file = self.get_paths(case_id, layer_idx)
        
        # Save tensor map and missing mask
        data = {
            "embeddings": {bb: t.cpu().float() for bb, t in bb_embeddings.items()},
            "missing_mask": missing_mask,
        }
        torch.save(data, emb_file)

        # Enhance metadata
        meta = {
            "case_id": case_id,
            "layer": layer_idx,
            "num_bbs": len(bb_embeddings),
            "missing_count": sum(1 for m in missing_mask.values() if m),
            **metadata,
        }
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    def load(
        self,
        case_id: str,
        layer_idx: int,
    ) -> Tuple[Dict[str, torch.Tensor], Dict[str, bool], Dict[str, Any]]:
        emb_file, meta_file = self.get_paths(case_id, layer_idx)
        if not emb_file.exists() or not meta_file.exists():
            raise FileNotFoundError(f"Cache missing for case {case_id} layer {layer_idx}")

        data = torch.load(emb_file, map_location="cpu", weights_only=True)
        with open(meta_file, "r", encoding="utf-8") as f:
            metadata = json.load(f)

        return data["embeddings"], data["missing_mask"], metadata


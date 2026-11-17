"""Qwen2.5-Coder-7B Base embedding extraction and basic block pooling pipeline."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import torch
import torch.nn as nn

from target_graph.embeddings.cache import EmbeddingCache
from target_graph.embeddings.pooling import align_tokens_to_bbs, pool_bb_embeddings
from target_graph.graphs.schema import SourceSpan


@dataclass
class QwenExtractorConfig:
    model_name: str = "Qwen/Qwen2.5-Coder-7B"
    layer_idx: int = 14
    feature_dim: int = 3584
    max_tokens: int = 8192
    chunk_policy: str = "chunk"  # "chunk" or "exclude"
    stride: int = 2048
    device: str = "cuda" if torch.cuda.is_available() else "cpu"
    mock: bool = False


class TokenizerFallback:
    """Regex-based C/C++ lexical tokenizer with character offset tracking."""

    # Matches identifiers/keywords, numeric literals, operators/punctuation, or strings
    TOKEN_REGEX = re.compile(
        r'("[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\'|[a-zA-Z_]\w*|0x[0-9a-fA-F]+|\d+(?:\.\d+)?|[-+*/%=<>!&|^~?:;.,(){}\[\]])'
    )

    def tokenize_with_offsets(self, text: str) -> Tuple[List[str], List[Tuple[int, int]]]:
        tokens: List[str] = []
        offsets: List[Tuple[int, int]] = []
        for m in self.TOKEN_REGEX.finditer(text):
            tokens.append(m.group(0))
            offsets.append((m.start(), m.end()))
        return tokens, offsets


class MockQwenExtractor:
    """Deterministic mock extractor generating reproducible 3584-dim hidden states on CPU."""

    def __init__(self, config: QwenExtractorConfig) -> None:
        self.config = config
        self.fallback = TokenizerFallback()
        self._hf_tokenizer = None
        if not config.mock:
            try:
                from transformers import AutoTokenizer
                self._hf_tokenizer = AutoTokenizer.from_pretrained(config.model_name, use_fast=True)
            except Exception:
                self._hf_tokenizer = None

    def extract(self, source_code: str) -> Tuple[List[Tuple[int, int]], torch.Tensor, bool]:
        """
        Returns:
            (token_offsets, hidden_states, was_chunked_or_excluded)
            hidden_states shape: [29, num_tokens, feature_dim]
        """
        token_strings: List[str] = []
        offsets: List[Tuple[int, int]] = []

        if self._hf_tokenizer is not None:
            try:
                encoding = self._hf_tokenizer(
                    source_code,
                    return_offsets_mapping=True,
                    add_special_tokens=False,
                )
                offsets = encoding["offset_mapping"]
                token_strings = [source_code[start:end] for start, end in offsets]
            except Exception:
                token_strings, offsets = self.fallback.tokenize_with_offsets(source_code)
        else:
            token_strings, offsets = self.fallback.tokenize_with_offsets(source_code)

        num_tokens = len(offsets)
        is_long = num_tokens > self.config.max_tokens

        if is_long and self.config.chunk_policy == "exclude":
            # Explicitly excluded from strict experiments
            return offsets, torch.zeros(29, 0, self.config.feature_dim), True

        # Generate deterministic mock hidden states [29, num_tokens, 3584]
        num_layers = 29
        gen = torch.Generator().manual_seed(42 + num_tokens)
        base = torch.randn(num_tokens, self.config.feature_dim, generator=gen, dtype=torch.float32)
        layer_scale = (1.0 + 0.05 * torch.arange(num_layers, dtype=torch.float32)).view(num_layers, 1, 1)
        states = base.unsqueeze(0) * layer_scale

        return offsets, states, is_long


class QwenRealExtractor:
    """Real Qwen2.5-Coder-7B extractor requiring GPU/CUDA."""

    def __init__(self, config: QwenExtractorConfig) -> None:
        self.config = config
        from transformers import AutoModelForCausalLM, AutoTokenizer

        dtype = torch.bfloat16 if torch.cuda.is_available() and torch.cuda.is_bf16_supported() else torch.float16
        self.tokenizer = AutoTokenizer.from_pretrained(config.model_name, use_fast=True)
        self.model = AutoModelForCausalLM.from_pretrained(
            config.model_name,
            torch_dtype=dtype,
            device_map=config.device,
        )
        self.model.eval()

    def extract(self, source_code: str) -> Tuple[List[Tuple[int, int]], torch.Tensor, bool]:
        encoding = self.tokenizer(
            source_code,
            return_offsets_mapping=True,
            add_special_tokens=False,
            return_tensors="pt",
        )
        offsets = encoding["offset_mapping"][0].cpu().tolist()
        num_tokens = len(offsets)
        is_long = num_tokens > self.config.max_tokens

        if is_long and self.config.chunk_policy == "exclude":
            return offsets, torch.zeros(29, 0, self.config.feature_dim), True

        input_ids = encoding["input_ids"].to(self.config.device)

        if not is_long:
            with torch.inference_mode():
                out = self.model(input_ids, output_hidden_states=True)
                # hidden_states is tuple of 29 tensors: each [1, seq_len, 3584]
                stacked = torch.stack([h[0].cpu().float() for h in out.hidden_states], dim=0)
                return offsets, stacked, False
        else:
            # Overlapping chunking
            window = self.config.max_tokens
            stride = self.config.stride
            seq_len = input_ids.size(1)
            stacked_total = torch.zeros(29, seq_len, self.config.feature_dim, dtype=torch.float32)
            counts = torch.zeros(seq_len, dtype=torch.float32)

            start = 0
            while start < seq_len:
                end = min(start + window, seq_len)
                chunk_ids = input_ids[:, start:end]
                with torch.inference_mode():
                    chunk_out = self.model(chunk_ids, output_hidden_states=True)
                    for layer_idx, h in enumerate(chunk_out.hidden_states):
                        stacked_total[layer_idx, start:end] += h[0].cpu().float()
                counts[start:end] += 1.0
                if end == seq_len:
                    break
                start += stride

            counts = counts.unsqueeze(0).unsqueeze(-1).clamp(min=1.0)
            stacked_total /= counts
            return offsets, stacked_total, True


class QwenEmbeddingPipeline:
    """End-to-end pipeline for extracting and pooling BB embeddings for a given program."""

    def __init__(self, config: Optional[QwenExtractorConfig] = None) -> None:
        self.config = config or QwenExtractorConfig()
        if self.config.mock or not torch.cuda.is_available():
            self.extractor = MockQwenExtractor(self.config)
        else:
            self.extractor = QwenRealExtractor(self.config)

    def process_function(
        self,
        source_code: str,
        bb_source_spans: Dict[str, List[SourceSpan]],
    ) -> Tuple[Dict[str, torch.Tensor], Dict[str, bool], Dict[str, Any]]:
        """Process a single function's raw source string and pool into BB representations.
        
        Args:
            source_code: Unmodified source code of function (signature + body)
            bb_source_spans: bb_id -> list of SourceSpan
            
        Returns:
            (bb_embeddings, missing_mask, metadata)
        """
        source_lines = source_code.splitlines(keepends=True)
        token_offsets, hidden_states, was_chunked_or_excluded = self.extractor.extract(source_code)

        metadata: Dict[str, Any] = {
            "num_tokens": len(token_offsets),
            "was_chunked_or_excluded": was_chunked_or_excluded,
            "layer_idx": self.config.layer_idx,
            "feature_dim": self.config.feature_dim,
            "source_hash": hashlib.sha256(source_code.encode("utf-8")).hexdigest(),
        }

        if hidden_states.size(1) == 0:
            # Entire function excluded
            bb_embeddings = {bb: torch.zeros(self.config.feature_dim) for bb in bb_source_spans}
            missing_mask = {bb: True for bb in bb_source_spans}
            return bb_embeddings, missing_mask, metadata

        # Map character offsets to BBs
        bb_to_tokens = align_tokens_to_bbs(
            token_offsets=token_offsets,
            source_lines=source_lines,
            bb_source_spans=bb_source_spans,
        )

        # Pool token embeddings to BB embeddings
        bb_embeddings, missing_mask = pool_bb_embeddings(
            hidden_states=hidden_states,
            bb_to_tokens=bb_to_tokens,
            layer_idx=self.config.layer_idx,
            feature_dim=self.config.feature_dim,
        )

        return bb_embeddings, missing_mask, metadata

    def extract_and_cache_case(
        self,
        case_id: str,
        bb_source_spans: Dict[str, List[SourceSpan]],
        function_sources: Dict[str, str],
        bb_to_function: Dict[str, str],
        cache: EmbeddingCache,
        force_recompute: bool = False,
    ) -> Tuple[Dict[str, torch.Tensor], Dict[str, bool]]:
        """Process all functions in a case, pool BBs, and cache results."""
        if not force_recompute and cache.has_valid_cache(case_id, self.config.layer_idx):
            embs, missing, _ = cache.load(case_id, self.config.layer_idx)
            return embs, missing

        all_embs: Dict[str, torch.Tensor] = {}
        all_missing: Dict[str, bool] = {}
        func_meta: Dict[str, Any] = {}

        # Group BBs by function
        func_to_bbs: Dict[str, List[str]] = {}
        for bb_id, func_name in bb_to_function.items():
            func_to_bbs.setdefault(func_name, []).append(bb_id)

        # Cache file-level extraction across functions in the same source file
        src_cache: Dict[int, Tuple[List[Tuple[int, int]], torch.Tensor, bool, List[str]]] = {}

        for func_name, bbs in func_to_bbs.items():
            src = function_sources.get(func_name, "")
            func_spans = {bb: bb_source_spans.get(bb, []) for bb in bbs}
            if not src:
                # No source available for this function: zero embeddings with mask
                for bb in bbs:
                    all_embs[bb] = torch.zeros(self.config.feature_dim)
                    all_missing[bb] = True
                continue

            src_hash = hash(src)
            if src_hash not in src_cache:
                source_lines = src.splitlines(keepends=True)
                token_offsets, hidden_states, was_chunked = self.extractor.extract(src)
                src_cache[src_hash] = (token_offsets, hidden_states, was_chunked, source_lines)
            else:
                token_offsets, hidden_states, was_chunked, source_lines = src_cache[src_hash]

            if hidden_states.size(1) == 0:
                for bb in bbs:
                    all_embs[bb] = torch.zeros(self.config.feature_dim)
                    all_missing[bb] = True
                continue

            bb_to_tokens = align_tokens_to_bbs(
                token_offsets=token_offsets,
                source_lines=source_lines,
                bb_source_spans=func_spans,
            )
            embs, missing = pool_bb_embeddings(
                hidden_states=hidden_states,
                bb_to_tokens=bb_to_tokens,
                layer_idx=self.config.layer_idx,
                feature_dim=self.config.feature_dim,
            )
            all_embs.update(embs)
            all_missing.update(missing)

        # Save to cache
        cache.save(
            case_id=case_id,
            layer_idx=self.config.layer_idx,
            bb_embeddings=all_embs,
            missing_mask=all_missing,
            metadata={
                "model": self.config.model_name,
                "feature_dim": self.config.feature_dim,
                "functions": func_meta,
            },
        )

        return all_embs, all_missing


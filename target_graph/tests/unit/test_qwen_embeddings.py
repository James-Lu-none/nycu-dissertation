"""Unit tests for Milestone 4: Qwen2.5-Coder-7B BB embedding extraction and caching."""
from __future__ import annotations

import json
from pathlib import Path
import pytest
import torch

from target_graph.embeddings.cache import EmbeddingCache
from target_graph.embeddings.pooling import align_tokens_to_bbs, pool_bb_embeddings
from target_graph.embeddings.qwen import (
    MockQwenExtractor,
    QwenEmbeddingPipeline,
    QwenExtractorConfig,
    TokenizerFallback,
)
from target_graph.graphs.schema import SourceSpan


@pytest.fixture
def sample_function_source() -> str:
    return (
        "int compute(int x, int y) {\n"
        "    int result = 0;\n"
        "    if (x > 10) {\n"
        "        result = x * 2;\n"
        "    } else {\n"
        "        result = y + 5;\n"
        "    }\n"
        "    return result;\n"
        "}\n"
    )


def test_tokenizer_fallback_offsets(sample_function_source: str):
    """Test that lexical tokenizer extracts accurate character offsets."""
    tokenizer = TokenizerFallback()
    tokens, offsets = tokenizer.tokenize_with_offsets(sample_function_source)
    
    assert len(tokens) > 0
    assert len(tokens) == len(offsets)
    for tok, (s, e) in zip(tokens, offsets):
        assert sample_function_source[s:e] == tok


def test_token_to_bb_alignment_and_pooling(sample_function_source: str):
    """Test offset alignment to BB source spans and arithmetic mean pooling."""
    lines = sample_function_source.splitlines(keepends=True)
    tokenizer = TokenizerFallback()
    _, offsets = tokenizer.tokenize_with_offsets(sample_function_source)

    # Define synthetic BB spans:
    # bb_entry: lines 1-3
    # bb_true: line 4
    # bb_false: line 6
    # bb_empty: line 100 (non-existent, missing)
    spans = {
        "bb_entry": [SourceSpan(file="test.c", start_line=1, end_line=3)],
        "bb_true": [SourceSpan(file="test.c", start_line=4, end_line=4)],
        "bb_false": [SourceSpan(file="test.c", start_line=6, end_line=6)],
        "bb_empty": [SourceSpan(file="test.c", start_line=100, end_line=100)],
    }

    bb_to_tokens = align_tokens_to_bbs(offsets, lines, spans)
    assert len(bb_to_tokens["bb_entry"]) > 0
    assert len(bb_to_tokens["bb_true"]) > 0
    assert len(bb_to_tokens["bb_false"]) > 0
    assert len(bb_to_tokens["bb_empty"]) == 0

    # Test pooling arithmetic
    seq_len = len(offsets)
    num_layers = 29
    hidden_dim = 3584
    mock_hidden = torch.randn(num_layers, seq_len, hidden_dim)

    layer_idx = 14
    embs, missing = pool_bb_embeddings(
        hidden_states=mock_hidden,
        bb_to_tokens=bb_to_tokens,
        layer_idx=layer_idx,
        feature_dim=hidden_dim,
    )

    # Check non-empty BB matches arithmetic mean
    true_tokens = bb_to_tokens["bb_true"]
    expected_true_vec = mock_hidden[layer_idx, true_tokens].mean(dim=0)
    assert torch.allclose(embs["bb_true"], expected_true_vec, atol=1e-6)
    assert not missing["bb_true"]

    # Check empty BB is zero vector with missing_mask == True
    assert torch.all(embs["bb_empty"] == 0.0)
    assert missing["bb_empty"] is True


def test_long_function_handling(sample_function_source: str):
    """Test policy handling when function exceeds max_tokens."""
    # Config with artificially low max_tokens = 5
    config_exclude = QwenExtractorConfig(max_tokens=5, chunk_policy="exclude", mock=True)
    pipeline_exclude = QwenEmbeddingPipeline(config_exclude)
    
    spans = {"bb_1": [SourceSpan(file="test.c", start_line=1, end_line=5)]}
    embs_exc, miss_exc, meta_exc = pipeline_exclude.process_function(sample_function_source, spans)
    
    assert meta_exc["was_chunked_or_excluded"] is True
    assert miss_exc["bb_1"] is True
    assert torch.all(embs_exc["bb_1"] == 0.0)

    # Config with chunking policy
    config_chunk = QwenExtractorConfig(max_tokens=10, stride=5, chunk_policy="chunk", mock=True)
    pipeline_chunk = QwenEmbeddingPipeline(config_chunk)
    embs_chk, miss_chk, meta_chk = pipeline_chunk.process_function(sample_function_source, spans)
    
    assert meta_chk["was_chunked_or_excluded"] is True
    assert not miss_chk["bb_1"]
    assert embs_chk["bb_1"].shape == (3584,)


def test_embedding_cache_roundtrip(tmp_path: Path):
    """Test saving and loading embedding cache with metadata validation."""
    cache = EmbeddingCache(tmp_path)
    case_id = "test_case_01"
    layer_idx = 14
    
    bb_embs = {
        "bb_01": torch.randn(3584),
        "bb_02": torch.zeros(3584),
    }
    missing_mask = {"bb_01": False, "bb_02": True}
    meta = {"model": "Qwen/Qwen2.5-Coder-7B", "feature_dim": 3584, "source_hash": "abc123hash"}

    cache.save(case_id, layer_idx, bb_embs, missing_mask, meta)
    assert cache.has_valid_cache(case_id, layer_idx, expected_source_hash="abc123hash")
    assert not cache.has_valid_cache(case_id, layer_idx, expected_source_hash="wrong_hash")

    loaded_embs, loaded_missing, loaded_meta = cache.load(case_id, layer_idx)
    assert set(loaded_embs.keys()) == {"bb_01", "bb_02"}
    assert torch.allclose(loaded_embs["bb_01"], bb_embs["bb_01"], atol=1e-6)
    assert loaded_missing == missing_mask
    assert loaded_meta["num_bbs"] == 2
    assert loaded_meta["missing_count"] == 1


def test_synthetic_fixture_qwen_extraction(tmp_path: Path):
    """Milestone 4 Acceptance Check: Extract Qwen embeddings for synthetic C fixture."""
    root = Path(__file__).resolve().parents[2]
    synthetic_c = root / "tests" / "fixtures" / "synthetic" / "synthetic_target.c"
    src_text = synthetic_c.read_text(encoding="utf-8")

    config = QwenExtractorConfig(mock=True, layer_idx=14, feature_dim=3584)
    pipeline = QwenEmbeddingPipeline(config)

    # BB spans for process_and_fault function
    spans = {
        "055516ffff04ff03": [SourceSpan(file="synthetic_target.c", start_line=53, end_line=53)],
        "ffffff772bffff34": [SourceSpan(file="synthetic_target.c", start_line=38, end_line=48)],
    }

    embs, missing, meta = pipeline.process_function(src_text, spans)
    assert "055516ffff04ff03" in embs
    assert embs["055516ffff04ff03"].shape == (3584,)
    assert not missing["055516ffff04ff03"]
    assert meta["feature_dim"] == 3584


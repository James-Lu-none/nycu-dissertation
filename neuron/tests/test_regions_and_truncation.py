import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import torch
from transformers import RobertaConfig, RobertaModel

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.mapper import (prepare_code_input, aggregate_region_activations,
                         get_line_level_activations)
from core.regions import get_aligned_regions
from core.direction import compute_line_representation, score_target_line
from attention_baseline import calculate_line_attention_scores
from neuron import extract_all_layers


class CharacterTokenizer:
    """Deterministic offline fixture: two special tokens plus one per character."""
    def __call__(self, code, truncation=False, max_length=None,
                 return_tensors=None, **kwargs):
        chars = list(enumerate(code))
        if truncation:
            chars = chars[:max_length - 2]
        ids = [0] + [3 + ord(c) % 50 for _, c in chars] + [2]
        offsets = [(0, 0)] + [(i, i + 1) for i, _ in chars] + [(0, 0)]
        result = dict(input_ids=ids, attention_mask=[1] * len(ids),
                      offset_mapping=offsets)
        if return_tensors:
            result = {k: torch.tensor([v]) for k, v in result.items()}
        return result


class RegionTests(unittest.TestCase):
    def test_insertion_and_deletion_use_matched_context(self):
        before, after = 'a\nb\nc', 'a\nx\nb\nc'
        self.assertEqual(get_aligned_regions(before, after), ([0, 1], [0, 1, 2]))
        self.assertEqual(get_aligned_regions(after, before), ([0, 1, 2], [0, 1]))
        self.assertEqual(get_aligned_regions(before, after, 0), ([], [1]))

    def test_boundaries_overlap_and_unchanged(self):
        self.assertEqual(get_aligned_regions('a\nb', 'x\na\nb'), ([0], [0, 1]))
        self.assertEqual(get_aligned_regions('a\nb', 'a\nb\nx'), ([1], [1, 2]))
        self.assertEqual(get_aligned_regions('a\nb', 'a\nb'), ([], []))
        self.assertEqual(get_aligned_regions('a\nb\nc\nd\ne', 'a\nx\nc\ny\ne'),
                         (list(range(5)), list(range(5))))
        with self.assertRaises(ValueError):
            get_aligned_regions('a', 'b', -1)

    def test_token_and_line_weighting_are_distinct(self):
        acts = torch.tensor([[1., 4.], [3., 2.], [8., 0.]])
        token_mean, line_mean = aggregate_region_activations(
            acts, {0: 0, 1: 0, 2: 1}, [0, 1, 2], 3)
        torch.testing.assert_close(token_mean, torch.tensor([4., 2.]))
        torch.testing.assert_close(line_mean, torch.tensor([5., 1.5]))
        weights = torch.tensor([[1., -2.], [3., 4.]])
        projected = compute_line_representation(line_mean, [0, 1], weights)
        lines = get_line_level_activations(acts, {0: 0, 1: 0, 2: 1}, 3)
        expected = torch.stack([compute_line_representation(a, [0, 1], weights)
                                for a in lines[:2]]).mean(0)
        torch.testing.assert_close(projected, expected)

    def test_signed_projection_preserves_magnitude(self):
        reps = torch.tensor([[2., 0.], [20., 0.], [-3., 4.]])
        torch.testing.assert_close(score_target_line(reps, torch.tensor([2., 0.])),
                                   torch.tensor([2., 20., -3.]))
        torch.testing.assert_close(score_target_line(reps, torch.zeros(2)), torch.zeros(3))


class CoverageTests(unittest.TestCase):
    def test_partial_and_missing_lines_are_not_valid(self):
        inputs, _, valid, truncated = prepare_code_input(
            'ab\ncdef\ngh', CharacterTokenizer(), max_length=7)
        self.assertEqual(inputs['input_ids'].shape[1], 7)
        self.assertEqual(valid, {0})
        self.assertEqual(truncated, {1, 2})

    def test_exact_fit_and_tokenless_line(self):
        _, _, valid, truncated = prepare_code_input('ab\n', CharacterTokenizer(), 5)
        self.assertEqual(valid, {0})
        self.assertEqual(truncated, set())

    def test_duplicate_unicode_offsets_require_all_tokens(self):
        def tokenizer(code, truncation=False, return_tensors=None, **kwargs):
            offsets = [(0, 0), (0, 1), (0, 1), (0, 0)]
            if truncation:
                offsets.pop(2)
            result = dict(input_ids=[0] * len(offsets), offset_mapping=offsets)
            return {k: torch.tensor([v]) for k, v in result.items()} if return_tensors else result
        _, _, valid, truncated = prepare_code_input('字', tokenizer, 3)
        self.assertEqual(valid, set())
        self.assertEqual(truncated, {0})


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tokenizer = CharacterTokenizer()
        self.model = RobertaModel(RobertaConfig(
            vocab_size=64, hidden_size=8, intermediate_size=12,
            num_hidden_layers=1, num_attention_heads=2,
            max_position_embeddings=514, hidden_dropout_prob=0.,
            attention_probs_dropout_prob=0.)).eval()

    def test_pair_filtering_and_summaries(self):
        # Keep one short pair. Skip one truncated changed region, one unchanged
        # pair and one insertion with no context on the vulnerable side.
        before = ['a\nb', 'a\n' + 'b' * 20, 'same', '']
        after = ['a\nx', 'a\n' + 'c' * 20, 'same', 'z']
        with contextlib.redirect_stdout(io.StringIO()), patch.object(
                self.model, 'forward', wraps=self.model.forward) as forward:
            summaries, extractors, stats, indices = extract_all_layers(
                before, after, self.tokenizer, self.model, [0], max_length=8)
        self.assertEqual(indices, [0])
        self.assertEqual(stats, dict(total=4, retained=1, skipped_no_changes=1,
                                    skipped_overlength_function=1, skipped_empty_region=1))
        self.assertEqual(forward.call_count, 2)
        self.assertEqual(summaries['vulnerable']['token_mean'][0].shape, (1, 12))
        # Independently reconstruct line and token means from the retained input.
        inputs, mapping, valid, _ = prepare_code_input(before[0], self.tokenizer, 8)
        with torch.no_grad():
            self.model(**inputs)
        acts = extractors[0].activations['encoder.layer.0.intermediate'][0]
        expected_lines = torch.stack([acts[[t for t, q2 in mapping.items() if q2 == q]].mean(0)
                                      for q in sorted(valid)]).mean(0)
        torch.testing.assert_close(summaries['vulnerable']['line_mean'][0][0], expected_lines)
        expected_tokens = acts[[t for t, q in mapping.items() if q >= 0]].mean(0)
        torch.testing.assert_close(summaries['vulnerable']['token_mean'][0][0], expected_tokens)
        for ext in extractors.values():
            ext.remove_hooks()

    def test_unselected_tail_also_rejects_pair(self):
        before, after = ['a\n' + 'b' * 20], ['x\n' + 'b' * 20]
        for context in (0, 1):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), patch.object(
                    self.model, 'forward', wraps=self.model.forward) as forward:
                with self.assertRaisesRegex(ValueError, 'No valid training pairs'):
                    extract_all_layers(before, after, self.tokenizer, self.model, [0],
                                       context_lines=context, max_length=8)
            self.assertIn('"skipped_overlength_function": 1', output.getvalue())
            forward.assert_not_called()
        self.assertFalse(self.model.encoder.layer[0].intermediate._forward_hooks)

    def test_exact_512_and_either_side_overlength(self):
        # CharacterTokenizer adds two special tokens: 510 characters fit exactly.
        before = ['a' * 510, 'a' * 511, 'a', 'a' * 511]
        after = ['b' * 510, 'b', 'b' * 511, 'b' * 511]
        with contextlib.redirect_stdout(io.StringIO()), patch.object(
                self.model, 'forward', wraps=self.model.forward) as forward:
            _, extractors, stats, indices = extract_all_layers(
                before, after, self.tokenizer, self.model, [0])
        self.assertEqual(indices, [0])
        self.assertEqual(stats['retained'], 1)
        self.assertEqual(stats['skipped_overlength_function'], 3)
        self.assertEqual(sum(v for k, v in stats.items() if k.startswith('skipped_')),
                         stats['total'] - stats['retained'])
        self.assertEqual(forward.call_count, 2)
        for call in forward.call_args_list:
            self.assertEqual(call.kwargs['input_ids'].shape[1], 512)
        for ext in extractors.values():
            ext.remove_hooks()

    def test_baseline_truncates_and_marks_partial_line(self):
        scores = calculate_line_attention_scores('a\n' + 'b' * 600, self.model, self.tokenizer)
        self.assertTrue(torch.isfinite(scores[0]))
        self.assertTrue(torch.isnan(scores[1]))

    def test_mismatched_pairs_fail(self):
        with self.assertRaisesRegex(ValueError, 'equal lengths'):
            extract_all_layers(['a'], [], self.tokenizer, self.model, [0])


if __name__ == '__main__':
    unittest.main()

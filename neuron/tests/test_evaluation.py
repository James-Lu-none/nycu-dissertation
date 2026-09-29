import contextlib
import io
import sys
import unittest
from pathlib import Path
import torch
from transformers import RobertaConfig, RobertaModel
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.evaluation import localization_metrics, evaluate_localization, select_layer
from core.hook_utils import ActivationExtractor
from test_regions_and_truncation import CharacterTokenizer


class EvaluationTests(unittest.TestCase):
    def test_rank_and_conservative_ties(self):
        self.assertEqual(localization_metrics({0: 3., 1: 2., 2: 1.}, {1}),
                         dict(hit_at_1=0., hit_at_5=1., mrr=.5))
        self.assertEqual(localization_metrics({0: 2., 1: 2., 2: 2.}, {1})['mrr'], 1/3)
        self.assertEqual(localization_metrics({0: 2., 1: 2., 2: 1.}, {0, 1})['mrr'], 1.)
        self.assertIsNone(localization_metrics({0: 1.}, {1}))

    def test_selection_uses_validation_only_and_rejects_empty(self):
        directions = {0: {'d_v': torch.ones(2)}, 1: {'d_v': torch.ones(2)},
                      2: {'d_v': torch.zeros(2)}}
        report = {'counts': {'evaluated_pairs': 2},
                  'layers': {0: {'mrr': .4}, 1: {'mrr': .7}, 2: {'mrr': 1.}}}
        self.assertEqual(select_layer(report, directions), 1)
        report['layers'][0]['mrr'] = .7
        self.assertEqual(select_layer(report, directions), 0)
        report['counts']['evaluated_pairs'] = 0
        with self.assertRaises(ValueError):
            select_layer(report, directions)

    def test_held_out_forward_and_proxy_exclusions(self):
        model = RobertaModel(RobertaConfig(
            vocab_size=64, hidden_size=8, intermediate_size=12,
            num_hidden_layers=1, num_attention_heads=2,
            max_position_embeddings=514, hidden_dropout_prob=0.,
            attention_probs_dropout_prob=0.)).eval()
        extractor = ActivationExtractor(model, 0)
        info = {'target_neurons': [0, 1], 'down_proj': extractor.get_down_projection_weights(),
                'd_v': torch.ones(8)}
        records = [({'code': 'a\nb'}, {'code': 'a\nx'}),
                   ({'code': 'a\nb'}, {'code': 'a\nx\nb'}),
                   ({'code': 'b'*511}, {'code': 'x'})]
        snapshot = info['d_v'].clone()
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                report = evaluate_localization(records, [0, 1, 2], CharacterTokenizer(),
                                               model, {0: extractor}, {0: info})
            self.assertEqual(report['counts']['evaluated_pairs'], 1)
            self.assertEqual(report['counts']['skipped_no_changed_lines'], 1)
            self.assertEqual(report['counts']['skipped_overlength_function'], 1)
            self.assertTrue(0 < report['layers'][0]['mrr'] <= 1)
            torch.testing.assert_close(info['d_v'], snapshot)
        finally:
            extractor.remove_hooks()

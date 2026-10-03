import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import torch
from transformers import ModernBertConfig, ModernBertModel
import neuron
from test_regions_and_truncation import CharacterTokenizer


class MainPipelineTests(unittest.TestCase):
    def test_train_fit_validation_selection_test_report(self):
        records = [({'id': str(i), 'code': f'v{i}\nx'},
                    {'id': str(i), 'code': f'p{i}\nx'}) for i in range(20)]
        model = ModernBertModel(ModernBertConfig(
            vocab_size=64, hidden_size=8, intermediate_size=12,
            num_hidden_layers=12, num_attention_heads=2,
            max_position_embeddings=8192, reference_compile=False, pad_token_id=0,
            bos_token_id=1, eos_token_id=2, cls_token_id=1, sep_token_id=2,
            attention_probs_dropout_prob=0.)).eval()
        with tempfile.TemporaryDirectory() as folder, contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(patch.object(neuron, '__file__', str(Path(folder)/'neuron.py')))
            stack.enter_context(patch('sys.argv', ['neuron.py', '--dataset', __file__]))
            stack.enter_context(patch.object(neuron, 'load_unified_records', return_value=records))
            stack.enter_context(patch.object(neuron, 'load_tokenizer',
                                            return_value=(CharacterTokenizer(), 'test')))
            stack.enter_context(patch.object(neuron, 'load_encoder', return_value=model))
            stack.enter_context(patch.object(neuron.torch.cuda, 'is_available', return_value=False))
            stack.enter_context(patch.object(neuron, 'plot_all_layers'))
            stack.enter_context(patch.object(neuron, 'plot_all_layers_pca'))
            (Path(folder) / 'neuron.py').write_text('# test script')
            neuron.main()
            report = json.loads(next((Path(folder)/'outputs').glob('neuron_modernbert_*/report.json')).read_text())
        self.assertEqual(report['train_filtering']['total'], 14)
        self.assertEqual(set(report['retained_train_indices']), set(report['splits']['train']))
        self.assertEqual(report['validation']['counts']['total_pairs'], 3)
        self.assertEqual(len(report['validation']['layers']), 12)
        self.assertEqual(list(report['test']['layers']), [str(report['selected_layer'])])
        for layer in model.layers:
            self.assertFalse(layer.mlp.Wo._forward_pre_hooks)

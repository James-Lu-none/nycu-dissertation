import unittest
import torch
from transformers import ModernBertConfig, ModernBertModel
from core.hook_utils import ActivationExtractor
from core.model_config import MAX_LENGTH
from attention_baseline import calculate_line_attention_scores
from test_regions_and_truncation import CharacterTokenizer


class ModernBertTests(unittest.TestCase):
    def test_gated_activation_reconstructs_ffn(self):
        model = ModernBertModel(ModernBertConfig(
            vocab_size=64, hidden_size=8, intermediate_size=12,
            num_hidden_layers=2, num_attention_heads=2, reference_compile=False,
            pad_token_id=0, bos_token_id=1, eos_token_id=2, cls_token_id=1, sep_token_id=2,
            attn_implementation='sdpa')).eval()
        ext = ActivationExtractor(model, 0)
        h = torch.randn(1, 7, 8)
        mlp = model.layers[0].mlp
        with torch.no_grad():
            expected = mlp(h)
            u, g = mlp.Wi(h).chunk(2, -1)
        torch.testing.assert_close(ext.activation, mlp.act(u) * g)
        torch.testing.assert_close(ext.activation @ ext.get_down_projection_weights(), expected)
        ext.remove_hooks()
        self.assertFalse(mlp.Wo._forward_pre_hooks)

    def test_streaming_attention_matches_full(self):
        model = ModernBertModel(ModernBertConfig(
            vocab_size=64, hidden_size=8, intermediate_size=12,
            num_hidden_layers=2, num_attention_heads=2, reference_compile=False,
            local_attention=4, global_attn_every_n_layers=2,
            pad_token_id=0, bos_token_id=1, eos_token_id=2, cls_token_id=1, sep_token_id=2,
            attn_implementation='eager')).eval()
        tokenizer = CharacterTokenizer()
        code = 'abcdef'
        from core.mapper import prepare_code_input
        inputs, mapping, _, _ = prepare_code_input(code, tokenizer)
        with torch.no_grad():
            probs = torch.stack(model(**inputs, output_attentions=True).attentions)
        columns = probs.mean((0, 1, 2)).sum(0)
        expected = sum(columns[t] for t, line in mapping.items() if line == 0)
        model.config._attn_implementation = 'sdpa'
        actual = calculate_line_attention_scores(code, model, tokenizer)
        torch.testing.assert_close(actual[0], expected)
        self.assertEqual(model.config._attn_implementation, 'sdpa')
        self.assertFalse(model.layers[0].attn._forward_hooks)
        self.assertEqual(MAX_LENGTH, 8192)

"""SDPA encoder with a differentiable, O(tokens) CLS attention readout."""
import torch
from torch import nn
from transformers import AutoModel, __version__

LEGACY = int(__version__.split(".")[0]) < 5
ATTENTION_BACKEND = "sdpa" if LEGACY else "rationale_sdpa"
from transformers.integrations.sdpa_attention import sdpa_attention_forward

MODELS = {'codebert': 'microsoft/codebert-base', 'modernbert': 'answerdotai/ModernBERT-base',
          'securebert2': 'cisco-ai/SecureBERT2.0-base'}


def cls_probabilities(query, key, mask, scaling):
    logits = (query[:, :, :1].float() @ key.float().transpose(-1, -2)) * scaling
    if mask is not None:
        mask = mask[..., :1, :key.shape[-2]]
        logits = logits.masked_fill(~mask, float('-inf')) if mask.dtype == torch.bool else logits + mask
    return logits.softmax(-1).mean(1).squeeze(1)


def cls_sdpa(module, query, key, value, attention_mask, scaling=None, **kwargs):
    if getattr(module, 'capture_cls', False):
        module.cls_attention = cls_probabilities(query, key, attention_mask,
                                                 scaling if scaling is not None else query.shape[-1] ** -.5)
    return sdpa_attention_forward(module, query, key, value, attention_mask, scaling=scaling, **kwargs)


if not LEGACY:
    from transformers import AttentionInterface, AttentionMaskInterface
    AttentionInterface.register('rationale_sdpa', cls_sdpa)
    AttentionMaskInterface.register('rationale_sdpa', AttentionMaskInterface._global_mapping['sdpa'])


def capture_legacy_cls(module, args, kwargs):
    """Read the selected layer's Q/K without replacing its native SDPA forward."""
    hidden = args[0] if args else kwargs['hidden_states']
    mask = kwargs.get('attention_mask')
    if hasattr(module, 'Wqkv'):
        from transformers.models.modernbert.modeling_modernbert import apply_rotary_pos_emb
        qkv = module.Wqkv(hidden).view(hidden.shape[0], -1, 3, module.num_heads, module.head_dim)
        cos, sin = module.rotary_emb(qkv, position_ids=kwargs['position_ids'])
        query, key, _ = qkv.transpose(3, 1).unbind(dim=2)
        query, key = apply_rotary_pos_emb(query, key, cos, sin)
    else:
        shape = (*hidden.shape[:-1], module.num_attention_heads, module.attention_head_size)
        query = module.query(hidden).view(shape).transpose(1, 2)
        key = module.key(hidden).view(shape).transpose(1, 2)
    module.cls_attention = cls_probabilities(query, key, mask, query.shape[-1] ** -.5)


class Classifier(nn.Module):
    def __init__(self, encoder, scoring="attention"):
        super().__init__()
        self.encoder = encoder
        self.scoring = scoring
        config = encoder.config
        if config.model_type == 'modernbert':
            config.reference_compile = False
            candidates = [i for i, layer in enumerate(encoder.layers)
                          if (layer.attn.local_attention == (-1, -1) if LEGACY
                              else layer.attention_type == 'full_attention')]
            self.attention_layer = candidates[-1]
            attention = encoder.layers[self.attention_layer].attn
        elif config.model_type == 'roberta':
            self.attention_layer = len(encoder.encoder.layer) - 1
            attention = encoder.encoder.layer[self.attention_layer].attention.self
        else:
            raise ValueError('Only ModernBERT and RoBERTa/CodeBERT are supported')
        attention.capture_cls = scoring == "attention"
        if LEGACY and scoring == "attention":
            attention.register_forward_pre_hook(capture_legacy_cls, with_kwargs=True)
        # Avoid registering the same module twice in state_dict.
        object.__setattr__(self, 'attention_module', attention)
        self.head = nn.Linear(config.hidden_size, 2)
        self.line_head = nn.Linear(config.hidden_size, 1) if scoring == "hidden" else None

    def forward(self, inputs):
        self.attention_module.cls_attention = None
        out = self.encoder(**inputs)
        if self.scoring == "hidden":
            return self.head(out.last_hidden_state[:, 0]), self.line_head(out.last_hidden_state).squeeze(-1)
        attention = self.attention_module.cls_attention
        if attention is None:
            raise RuntimeError('Differentiable CLS attention was not captured')
        return self.head(out.last_hidden_state[:, 0]), attention


def load_model(name, revision, scoring="attention", local_files_only=False):
    return Classifier(AutoModel.from_pretrained(MODELS.get(name, name), revision=revision,
                                               attn_implementation=ATTENTION_BACKEND,
                                               local_files_only=local_files_only), scoring=scoring)


def line_distribution(attention, line_ids, logits=False):
    """Mean tokens per line; linear(mean hidden) equals mean(linear(hidden))."""
    valid = line_ids >= 0
    if not valid.any():
        return attention.new_empty(0)
    ids = line_ids[valid]
    sums = attention.new_zeros(int(ids.max()) + 1).scatter_add(0, ids, attention[valid])
    counts = torch.bincount(ids, minlength=len(sums)).to(sums)
    means = sums / counts.clamp_min(1)
    return means.softmax(0) if logits else means / means.sum().clamp_min(1e-12)


def rationale_loss(attention, examples, mode):
    losses = []
    for row, example in zip(attention, examples):
        target = example['random'] if mode == 'random' else example['positive']
        if example['label'] != 1 or not target:
            continue
        distribution = line_distribution(row[:len(example['line_ids'])],
                                         torch.tensor(example['line_ids'], device=row.device), logits=mode == 'hidden')
        # Uniform over positive lines: CE equals KL up to a target-only constant.
        losses.append(-distribution[target].clamp_min(1e-12).log().mean())
    return torch.stack(losses).mean() if losses else attention.sum() * 0

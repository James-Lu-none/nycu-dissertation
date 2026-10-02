"""Shared encoder identity and input budget for audit and localization."""
MODEL_ID = 'answerdotai/ModernBERT-base'
MAX_LENGTH = 8192


def load_encoder(device='cpu'):
    from transformers import AutoModel
    # Preserve batch/sequence axes and observable Python hooks; no unpadding/compile.
    model = AutoModel.from_pretrained(
        MODEL_ID, attn_implementation='sdpa')
    if model.config.model_type != 'modernbert':
        raise ValueError('Expected ModernBERT')
    if model.config.max_position_embeddings < MAX_LENGTH:
        raise ValueError('Encoder context is shorter than the configured input budget')
    return model.to(device).eval()

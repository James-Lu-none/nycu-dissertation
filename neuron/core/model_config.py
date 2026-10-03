"""Shared encoder selection and loading for probes and localization."""
MODELS = {'modernbert': 'answerdotai/ModernBERT-base',
          'securebert2': 'cisco-ai/SecureBERT2.0-base'}
MODEL_ID = MODELS['modernbert']
MAX_LENGTH = 8192


def load_tokenizer(model=MODEL_ID, revision='main', max_length=MAX_LENGTH):
    from transformers import AutoConfig, AutoTokenizer
    model_id = MODELS.get(model, model)
    config = AutoConfig.from_pretrained(model_id, revision=revision)
    if config.model_type != 'modernbert':
        raise ValueError('Expected ModernBERT architecture')
    if not 0 < max_length <= config.max_position_embeddings:
        raise ValueError('Input budget must be positive and within encoder capacity')
    revision = getattr(config, '_commit_hash', None) or revision
    return AutoTokenizer.from_pretrained(model_id, revision=revision), revision


def load_encoder(device='cpu', model=MODEL_ID, revision='main', max_length=MAX_LENGTH):
    from transformers import AutoModel
    encoder = AutoModel.from_pretrained(
        MODELS.get(model, model), revision=revision, attn_implementation='sdpa')
    if encoder.config.model_type != 'modernbert':
        raise ValueError('Expected ModernBERT architecture')
    if not 0 < max_length <= encoder.config.max_position_embeddings:
        raise ValueError('Input budget must be positive and within encoder capacity')
    return encoder.to(device).eval()

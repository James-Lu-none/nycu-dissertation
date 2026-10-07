"""Versioned training summaries and fitted-model artifacts (local trusted files)."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import joblib
import torch
from .regions import get_aligned_regions
from .mapper import prepare_code_input


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def extraction_metadata(model, tokenizer, revision, records, context_lines, max_length, splits):
    weights = hashlib.sha256()
    for name, tensor in model.state_dict().items():
        weights.update(name.encode())
        weights.update(tensor.detach().cpu().contiguous().view(torch.uint8).numpy().tobytes())
    backend = getattr(tokenizer, 'backend_tokenizer', None)
    tokenizer_state = backend.to_str() if backend is not None else repr(type(tokenizer))
    sources = {name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
               for name in ('extraction.py', 'mapper.py', 'regions.py', 'hook_utils.py', 'training_artifacts.py')}
    return dict(format_version=1, model_type=model.config.model_type, revision=revision,
                weights_sha256=weights.hexdigest(), model_config=fingerprint(model.config.to_dict()),
                attention_backend=getattr(model.config, '_attn_implementation', None),
                tokenizer=fingerprint(tokenizer_state),
                train_records=fingerprint(records), splits=fingerprint(splits),
                context_lines=context_lines, max_length=max_length, implementation=sources,
                layers=model.config.num_hidden_layers, dtype='float32',
                region_lines='zero-based; complete valid lines only')


def build_cache(summaries, extractors, stats, retained_indices, records, metadata, tokenizer):
    projections = {layer: ext.get_down_projection_weights().cpu() for layer, ext in extractors.items()}
    contributions = {}
    for layer, weights in projections.items():
        norm = weights.norm(dim=1)
        v = summaries['vulnerable']['token_mean'][layer] * norm
        p = summaries['patched']['token_mean'][layer] * norm
        contributions[layer] = dict(vulnerable=v, patched=p, mean_delta=(v - p).mean(0))
    pairs = []
    for index in retained_indices:
        record = records[index]
        codes = [side['code'] for side in record]
        regions = get_aligned_regions(*codes, metadata['context_lines'])
        valid = [sorted(set(region) & prepare_code_input(code, tokenizer, metadata['max_length'])[2])
                 for region, code in zip(regions, codes)]
        pairs.append(dict(train_index=index, pair_id=fingerprint(record),
                          source_ids=[side.get('id') for side in record],
                          vulnerable_lines=valid[0], patched_lines=valid[1],
                          valid_line_counts=list(map(len, valid))))
    return dict(metadata=metadata, summaries=summaries, projections=projections,
                contributions=contributions, pairs=pairs, stats=stats,
                retained_indices=retained_indices)


def _atomic_write(path, writer):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    os.close(fd)
    try:
        writer(temporary)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_cache(path, payload):
    _atomic_write(path, lambda name: torch.save(payload, name))


def load_cache(path, metadata):
    payload = torch.load(path, map_location='cpu', weights_only=True)
    if payload['metadata'] != metadata:
        raise ValueError('Activation cache metadata mismatch')
    return payload


def save_models(path, bundle):
    _atomic_write(path, lambda name: joblib.dump(bundle, name))


def load_models(path):
    # joblib contains sklearn estimators. Only load your own trusted artifacts.
    return joblib.load(path)

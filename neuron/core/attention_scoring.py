"""Stream incoming attention reductions; never retain every layer's T x T maps."""
import torch
from .mapper import prepare_code_input


def attention_line_scores(code, model, tokenizer, max_length):
    inputs, mapping, valid, _ = prepare_code_input(code, tokenizer, max_length)
    received = None
    count = 0
    def collect(module, args, output):
        nonlocal received, count
        weights = output[1]
        if weights is None:
            raise ValueError('Attention probabilities unavailable; eager attention required')
        column = weights[0].float().mean(0).sum(0)
        received = column if received is None else received + column
        count += 1
        return (output[0], None, *output[2:])
    layers = (model.layers if model.config.model_type == 'modernbert' else model.encoder.layer)
    modules = [layer.attn if model.config.model_type == 'modernbert' else layer.attention for layer in layers]
    hooks = [module.register_forward_hook(collect) for module in modules]
    try:
        with torch.inference_mode():
            model(**{k: v.to(model.device) for k, v in inputs.items()}, output_attentions=True)
    finally:
        for hook in hooks:
            hook.remove()
    if count != len(layers):
        raise ValueError('Some attention layers were not captured')
    received = received.cpu()
    scores = {q: 0. for q in valid}
    for token, line in mapping.items():
        if line in scores:
            scores[line] += float(received[token])
    return scores

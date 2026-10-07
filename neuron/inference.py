"""Score a code file using validation-selected, trusted local model artifacts."""
import argparse
import json
from pathlib import Path
import torch
from core.training_artifacts import load_models
from core.model_config import load_tokenizer, load_encoder
from core.hook_utils import ActivationExtractor
from core.mapper import prepare_code_input, get_line_level_activations
from core.evaluation import window_scores
from core.direction import score_target_line


def score_code(code, tokenizer, model, bundle):
    inputs, mapping, valid, _ = prepare_code_input(code, tokenizer, bundle['metadata']['extraction']['max_length'])
    methods = bundle['models']
    extractors = {info['layer']: None for info in methods.values()}
    try:
        for layer in extractors:
            extractors[layer] = ActivationExtractor(model, layer)
        with torch.no_grad():
            model(**{k: v.to(model.device) for k, v in inputs.items()})
        lines = code.split('\n')
        scores = {}
        for method, info in methods.items():
            acts = get_line_level_activations(extractors[info['layer']].activation[0], mapping, len(lines))
            indices = info['target_neurons']
            reps = acts[:, indices] @ info['down_proj'][indices]
            if 'estimator' in info:
                raw = torch.from_numpy(info['estimator'].decision_function(reps.numpy()))
                values = torch.tanh(raw)
            else:
                values = reps @ info['d_v'] + info['bias'] if 'bias' in info else score_target_line(reps, info['d_v'])
            if 'window' in info:
                values = window_scores(values, valid, info['window'])
            scores[method] = [float(values[i]) if i in valid else None for i in range(len(lines))]
        return [dict(line=i + 1, code=line, scores={m: values[i] for m, values in scores.items()})
                for i, line in enumerate(lines)]
    finally:
        for ext in extractors.values():
            if ext is not None:
                ext.remove_hooks()


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--models', required=True)
    cli.add_argument('--code', required=True)
    cli.add_argument('--output', required=True)
    args = cli.parse_args()
    bundle = load_models(args.models)
    settings = bundle['metadata']
    name, revision = settings['training']['model'], settings['extraction']['revision']
    tokenizer, _ = load_tokenizer(name, revision)
    model = load_encoder('cuda' if torch.cuda.is_available() else 'cpu', name, revision)
    result = score_code(Path(args.code).read_text(), tokenizer, model, bundle)
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))


if __name__ == '__main__':
    main()

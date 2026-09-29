"""Held-out localization against changed-line proxy labels, not ground truth."""
import difflib
import torch
from tqdm import tqdm
from core.mapper import prepare_code_input, get_line_level_activations
from core.direction import score_target_line


def changed_vulnerable_lines(vulnerable, patched):
    matcher = difflib.SequenceMatcher(None, vulnerable.split('\n'), patched.split('\n'),
                                      autojunk=False)
    return {q for tag, a, b, _, _ in matcher.get_opcodes()
            if tag in ('replace', 'delete') for q in range(a, b)}


def localization_metrics(scores, positive_lines):
    """Rank the first positive line; ties put nonpositive lines first.

    scores maps valid line indices to finite scalar scores. Return None when
    the function has no valid positive lines. This avoids source-order tie bias.
    """
    positive = set(positive_lines) & scores.keys()
    if not positive:
        return None
    best = max(scores[q] for q in positive)
    rank = 1 + sum(value >= best for q, value in scores.items() if q not in positive)
    return {'hit_at_1': float(rank <= 1), 'hit_at_5': float(rank <= 5),
            'mrr': 1.0 / rank}


def evaluate_localization(records, indices, tokenizer, model, extractors,
                          layer_directions, description='Validation'):
    layers = list(layer_directions)
    totals = {l: dict(hit_at_1=0., hit_at_5=0., mrr=0.) for l in layers}
    counts = dict(total_pairs=len(indices), evaluated_pairs=0,
                  skipped_no_changed_lines=0, skipped_no_valid_labels=0,
                  skipped_overlength_function=0)
    for i in tqdm(indices, desc=description):
        vulnerable, patched = (record['code'] for record in records[i])
        if any(len(tokenizer(code, truncation=False, verbose=False)['input_ids']) > 512
               for code in (vulnerable, patched)):
            counts['skipped_overlength_function'] += 1
            continue
        labels = changed_vulnerable_lines(vulnerable, patched)
        if not labels:
            counts['skipped_no_changed_lines'] += 1
            continue
        inputs, mapping, valid_lines, _ = prepare_code_input(vulnerable, tokenizer)
        if not labels & valid_lines:
            counts['skipped_no_valid_labels'] += 1
            continue
        with torch.no_grad():
            for ext in extractors.values():
                ext.clear()
            model(**{k: v.to(model.device) for k, v in inputs.items()})
            for l, info in layer_directions.items():
                acts = extractors[l].activations[f'encoder.layer.{l}.intermediate'][0]
                line_acts = get_line_level_activations(acts, mapping, len(vulnerable.split('\n')))
                neurons = info['target_neurons']
                reps = line_acts[:, neurons] @ info['down_proj'][neurons]
                scores = score_target_line(reps, info['d_v'])
                if not torch.isfinite(scores).all():
                    raise ValueError(f'Nonfinite scores in {description}, pair {i}, layer {l}')
                metrics = localization_metrics({q: scores[q].item() for q in valid_lines}, labels)
                for key, value in metrics.items():
                    totals[l][key] += value
        counts['evaluated_pairs'] += 1
    n = counts['evaluated_pairs']
    metrics = {l: {key: value / n if n else None for key, value in values.items()}
               for l, values in totals.items()}
    print(f'{description} changed-line proxy counts: {counts}')
    for l, values in metrics.items():
        if n:
            print(f"Layer {l:2d} | Hit@1={values['hit_at_1']:.4f} | "
                  f"Hit@5={values['hit_at_5']:.4f} | MRR={values['mrr']:.4f}")
        else:
            print(f'Layer {l:2d} | no evaluable labels')
    return {'counts': counts, 'layers': metrics}


def select_layer(validation_report, layer_directions):
    if not validation_report['counts']['evaluated_pairs']:
        raise ValueError('Validation has no evaluable changed-line labels; cannot select a layer')
    usable = [l for l in validation_report['layers']
              if torch.isfinite(layer_directions[l]['d_v']).all()
              and torch.norm(layer_directions[l]['d_v']) > 0]
    if not usable:
        raise ValueError('No finite nonzero vulnerability direction is available')
    # Primary metric: MRR. Exact ties use the lower layer index, not test results.
    return max(usable, key=lambda l: (validation_report['layers'][l]['mrr'], -l))

from core.model_config import MODEL_ID, MAX_LENGTH, load_encoder
"""Held-out localization against changed-line proxy labels, not ground truth."""
import difflib
from concurrent.futures import ThreadPoolExecutor
from time import perf_counter
from threadpoolctl import threadpool_limits
from core.fit_jobs import worker_count
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


def random_ranking_metrics(n, positives):
    """Exact expectation under a uniformly random permutation of valid lines."""
    survival, mrr, hit5 = 1.0, 0.0, 0.0
    for rank in range(1, n - positives + 2):
        probability = survival * positives / (n - rank + 1)
        mrr += probability / rank
        if rank <= 5:
            hit5 += probability
        survival *= (n - rank + 1 - positives) / (n - rank + 1)
    return dict(hit_at_1=positives / n, hit_at_5=hit5, mrr=mrr)


def window_scores(scores, valid_lines, width):
    """Physical source-line windows; even widths include one extra following line."""
    result = scores.clone()
    n = len(scores)
    for q in valid_lines:
        if width == 'all':
            neighbors = sorted(valid_lines)
        else:
            w = int(width)
            neighbors = [j for j in range(max(0, q - (w - 1)//2), min(n, q + w//2 + 1))
                         if j in valid_lines]
        result[q] = scores[neighbors].mean()
    return result


def evaluate_localization(records, indices, tokenizer, model, extractors,
                          layer_directions, description='Validation', cpu_jobs=24):
    count = sum('estimator' in info for info in layer_directions.values())
    if not count:
        return _evaluate_localization(records, indices, tokenizer, model, extractors,
                                      layer_directions, description)
    workers = min(count, worker_count(cpu_jobs))
    print(f'{description}: {count} SVM candidates | CPU workers={workers} | valid lines only', flush=True)
    with threadpool_limits(limits=1), ThreadPoolExecutor(max_workers=workers) as pool:
        return _evaluate_localization(records, indices, tokenizer, model, extractors,
                                      layer_directions, description, pool)


def _evaluate_localization(records, indices, tokenizer, model, extractors,
                          layer_directions, description='Validation', pool=None):
    encoder_seconds = scoring_seconds = 0.
    random_totals = dict(hit_at_1=0., hit_at_5=0., mrr=0.)
    per_pair = []
    score_ranges = {k: {'min': None, 'max': None} for k in layer_directions}
    layers = list(layer_directions)
    totals = {l: dict(hit_at_1=0., hit_at_5=0., mrr=0.) for l in layers}
    counts = dict(total_pairs=len(indices), evaluated_pairs=0,
                  skipped_no_changed_lines=0, skipped_no_valid_labels=0,
                  skipped_overlength_function=0)
    for i in tqdm(indices, desc=description):
        vulnerable, patched = (record['code'] for record in records[i])
        if any(len(tokenizer(code, truncation=False, verbose=False)['input_ids']) > MAX_LENGTH
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
        random_metrics = random_ranking_metrics(len(valid_lines), len(labels & valid_lines))
        pair_result = {'index': i, 'valid_lines': len(valid_lines), 'positive_lines': len(labels & valid_lines),
                       'random': random_metrics, 'layers': {}}
        for key, value in random_metrics.items():
            random_totals[key] += value
        with torch.no_grad():
            for ext in extractors.values():
                ext.clear()
            started = perf_counter()
            model(**{k: v.to(model.device) for k, v in inputs.items()})
            encoder_seconds += perf_counter() - started
            started = perf_counter()
            cached_reps = {}
            pending_scores = {}
            svm_inputs = {}
            valid_order = sorted(valid_lines)
            for l, info in layer_directions.items():
                cache_key = (info.get('layer', l), info.get('representation', 'all'))
                if cache_key not in cached_reps:
                    acts = extractors[info.get('layer', l)].activation[0]
                    line_acts = get_line_level_activations(acts, mapping, len(vulnerable.split('\n')))
                    neurons = info['target_neurons']
                    cached_reps[cache_key] = line_acts[:, neurons] @ info['down_proj'][neurons]
                if 'estimator' in info:
                    # Share representations across candidates; score only retained lines.
                    if cache_key not in svm_inputs:
                        svm_inputs[cache_key] = cached_reps[cache_key][valid_order].cpu().numpy()
                    pending_scores[l] = pool.submit(info['estimator'].decision_function, svm_inputs[cache_key])
            for l, info in layer_directions.items():
                cache_key = (info.get('layer', l), info.get('representation', 'all'))
                reps = cached_reps[cache_key]
                if 'estimator' in info:
                    margins = torch.from_numpy(pending_scores[l].result())
                    scores = torch.zeros(len(reps), dtype=margins.dtype)
                    scores[valid_order] = margins
                else:
                    scores = (reps @ info['d_v'] + info['bias'] if 'bias' in info
                              else score_target_line(reps, info['d_v']))
                if 'window' in info:
                    scores = window_scores(scores, valid_lines, info['window'])
                if 'estimator' in info:
                    bounded = torch.tanh(scores[sorted(valid_lines)])
                    current = score_ranges[l]
                    current['min'] = min(current['min'], bounded.min().item()) if current['min'] is not None else bounded.min().item()
                    current['max'] = max(current['max'], bounded.max().item()) if current['max'] is not None else bounded.max().item()
                if not torch.isfinite(scores).all():
                    raise ValueError(f'Nonfinite scores in {description}, pair {i}, layer {l}')
                metrics = localization_metrics({q: scores[q].item() for q in valid_lines}, labels)
                pair_result['layers'][l] = metrics
                for key, value in metrics.items():
                    totals[l][key] += value
        scoring_seconds += perf_counter() - started
        per_pair.append(pair_result)
        counts['evaluated_pairs'] += 1
    n = counts['evaluated_pairs']
    metrics = {l: {key: value / n if n else None for key, value in values.items()}
               for l, values in totals.items()}
    print(f'{description} changed-line proxy counts: {counts}')
    print(f'{description} timing: encoder={encoder_seconds:.1f}s, representation/scoring/metrics={scoring_seconds:.1f}s', flush=True)
    for l, values in metrics.items():
        if n:
            print(f"Layer {l:2d} | Hit@1={values['hit_at_1']:.4f} | "
                  f"Hit@5={values['hit_at_5']:.4f} | MRR={values['mrr']:.4f}")
        else:
            print(f'Layer {l:2d} | no evaluable labels')
    return {'counts': counts, 'layers': metrics, 'per_pair': per_pair, 'score_ranges': score_ranges,
            'random_baseline': {k: v / n if n else None for k, v in random_totals.items()}}


def select_layer(validation_report, layer_directions):
    if not validation_report['counts']['evaluated_pairs']:
        raise ValueError('Validation has no evaluable changed-line labels; cannot select a layer')
    usable = [l for l in validation_report['layers']
              if 'estimator' in layer_directions[l] or (torch.isfinite(layer_directions[l]['d_v']).all()
              and torch.norm(layer_directions[l]['d_v']) > 0)]
    if not usable:
        raise ValueError('No finite nonzero vulnerability direction is available')
    # Primary metric: MRR. Exact ties use the lower layer index, not test results.
    return max(usable, key=lambda l: (validation_report['layers'][l]['mrr'], -l))

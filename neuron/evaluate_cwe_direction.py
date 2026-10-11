"""Known-CWE B diagnostic on an existing ALL experiment's exact held-out split."""
import argparse
from collections import Counter
import csv
import json
from pathlib import Path
import torch
from tqdm import tqdm
from core.cwe_direction import fit_directions, select_direction
from core.training_artifacts import load_models, load_cache, fingerprint, save_models
from core.splits import load_unified_records, split_pairs
from core.model_config import load_tokenizer, load_encoder
from core.mapper import prepare_code_input, get_line_level_activations
from core.hook_utils import ActivationExtractor
from core.direction import score_target_line
from core.evaluation import changed_vulnerable_lines, localization_metrics, random_ranking_metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', nargs='+', required=True)
    parser.add_argument('--reference-models', required=True, help='ALL inference_models.joblib')
    parser.add_argument('--training-cache', required=True, help='Matching training .pt from activation_cache')
    parser.add_argument('--min-train-pairs', type=int, default=100)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--cpu-threads', type=int, default=4)
    args = parser.parse_args()
    if args.min_train_pairs < 1 or args.cpu_threads < 1:
        parser.error('Counts must be positive')
    torch.set_num_threads(args.cpu_threads)
    bundle = load_models(args.reference_models)
    meta = bundle['metadata']
    settings, extraction = meta['training'], meta['extraction']
    if settings.get('cwe'):
        raise ValueError('Reference must be an ALL experiment')
    base = bundle['models']['B']
    layer, limit = base['layer'], extraction['max_length']
    cache = load_cache(args.training_cache, extraction)
    records = [p for path in args.dataset for p in load_unified_records(path)]
    tokenizer, revision = load_tokenizer(settings['model'], extraction['revision'], limit)
    eligible = [i for i, pair in enumerate(tqdm(records, desc='Verify split'))
                if all(len(tokenizer(s['code'], truncation=False, verbose=False)['input_ids']) <= limit for s in pair)]
    splits = split_pairs(records, eligible, settings['split_seed'])
    train = [records[i] for i in splits['train']]
    if fingerprint(splits) != extraction['splits'] or fingerprint(train) != extraction['train_records']:
        raise ValueError('Dataset/order/split does not match reference')
    retained = [train[i] for i in cache['retained_indices']]
    if [fingerprint(p) for p in retained] != [p['pair_id'] for p in cache['pairs']]:
        raise ValueError('Cache pair alignment mismatch')
    projection = cache['projections'][layer]
    if not torch.equal(projection, base['down_proj']) or len(base['target_neurons']) != len(projection):
        raise ValueError('Reference B must use matching all-neuron projection')
    summaries = cache['summaries']
    deltas = (summaries['vulnerable']['line_mean'][layer] - summaries['patched']['line_mean'][layer]) @ projection
    expected = deltas.mean(0)
    if not torch.allclose(expected / expected.norm().clamp_min(1e-30), base['d_v'], atol=1e-5, rtol=1e-4):
        raise ValueError('Cached ALL direction differs from reference')
    directions, train_counts = fit_directions(deltas, retained, args.min_train_pairs)
    del cache, summaries, deltas
    manifest = dict(version=1, diagnostic='known_CWE_metadata_required_not_code_only_inference',
                    model=settings['model'], layer=layer, cache_key=meta['cache_key'],
                    dataset=fingerprint(records), min_train_pairs=args.min_train_pairs,
                    routing='largest retained train count; lexical tie break; missing/small/zero direction -> ALL',
                    train_counts=train_counts, fitted_cwes=sorted(directions),
                    split_sizes={k: len(v) for k, v in splits.items()})
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = args.output_dir / 'run.json'
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError('Output directory belongs to another experiment')
    manifest_path.write_text(json.dumps(manifest, indent=2))
    save_models(args.output_dir / 'directions.joblib', dict(metadata=manifest, base=base, directions=directions))
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    model = load_encoder(device, settings['model'], revision, limit)
    model.config.reference_compile = False
    extractor = ActivationExtractor(model, layer)
    progress = args.output_dir / 'progress.jsonl'
    results = [json.loads(line) for line in progress.read_text().splitlines()] if progress.exists() else []
    done = {(r['split'], r['index']) for r in results}

    def summarize():
        rows = []
        counts = {}
        for split in ('validation', 'test'):
            entries = [r for r in results if r['split'] == split]
            evaluated = [r for r in entries if 'metrics' in r]
            counts[split] = dict(completed=len(entries), expected=len(splits[split]),
                                 evaluated=len(evaluated), exclusions=dict(Counter(r['skip'] for r in entries if 'skip' in r)),
                                 routes=dict(Counter(r['route'] for r in evaluated)))
            scopes = ['all', 'specialized', 'fallback']
            for scope in scopes:
                subset = [r for r in evaluated if scope == 'all' or (r['route'] == 'ALL') == (scope == 'fallback')]
                for method in ('B_ALL', 'B_known_CWE', 'random'):
                    if subset:
                        rows.append(dict(split=split, scope=scope, method=method, layer=layer, pairs=len(subset),
                                         complete=len(entries) == len(splits[split]),
                                         **{k: sum(r['metrics'][method][k] for r in subset)/len(subset)
                                            for k in ('hit_at_1', 'hit_at_5', 'mrr')}))
        (args.output_dir / 'counts.json').write_text(json.dumps(counts, indent=2))
        if rows:
            with (args.output_dir / 'report.csv').open('w', newline='') as stream:
                writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
                writer.writeheader(); writer.writerows(rows)

    try:
        with progress.open('a') as stream:
            for split in ('validation', 'test'):
                for i in tqdm(splits[split], desc=split):
                    if (split, i) in done:
                        continue
                    before, after = (s['code'] for s in records[i])
                    labels = changed_vulnerable_lines(before, after)
                    row = dict(split=split, index=i)
                    inputs, mapping, valid, _ = prepare_code_input(before, tokenizer, limit)
                    if not labels:
                        row['skip'] = 'no_changed_lines'
                    elif not labels & valid:
                        row['skip'] = 'no_valid_labels'
                    else:
                        route = select_direction(records[i], directions, train_counts)
                        with torch.inference_mode():
                            extractor.clear()
                            model(**{k: v.to(device) for k, v in inputs.items()})
                            acts = get_line_level_activations(extractor.activation[0], mapping, len(before.split('\n')))
                            reps = acts @ projection
                            metrics = {}
                            for name, direction in [('B_ALL', base['d_v']), ('B_known_CWE', directions.get(route, base['d_v']))]:
                                scores = score_target_line(reps, direction)
                                if not torch.isfinite(scores).all():
                                    raise ValueError('Nonfinite line scores')
                                metrics[name] = localization_metrics({q: scores[q].item() for q in valid}, labels)
                        row.update(route=route, metrics=dict(metrics, random=random_ranking_metrics(len(valid), len(labels & valid))))
                    stream.write(json.dumps(row) + '\n'); stream.flush()
                    results.append(row)
                    if len(results) % 25 == 0:
                        summarize()
    finally:
        extractor.remove_hooks()
        summarize()
    print(f'Results: {args.output_dir / "report.csv"}')


if __name__ == '__main__':
    main()

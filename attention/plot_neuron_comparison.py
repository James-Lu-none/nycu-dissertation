"""Rescore selected B/E models and plot line Hit@fraction against incoming attention.

Run from attention/: python plot_neuron_comparison.py --device cuda
B/E are adaptations inspired by safety knowledge neurons, not paper reproductions.
"""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import torch
from threadpoolctl import threadpool_limits
from tqdm import tqdm

from data import load_unified_records, fingerprint, load_models
from core.model_config import load_encoder, load_tokenizer
from core.hook_utils import ActivationExtractor
from core.mapper import prepare_code_input, get_line_level_activations
from core.direction import score_target_line
from core.evaluation import localization_metrics, changed_vulnerable_lines, random_ranking_metrics
from plot_top_fraction import curve, write_csv

ROOT = Path(__file__).resolve().parent
NEURON_RUN = ROOT.parent/'neuron/outputs/neuron_modernbert_20261010_131817_570904'
CLS_RUNS = ROOT/'outputs/pipeline_20261012_231316'


def rank_row(pair, lines, positive, scores):
    if len(lines) != len(scores) or not np.isfinite(scores).all():
        raise ValueError(f'Invalid scores for pair {pair}')
    metrics = localization_metrics(dict(zip(lines, map(float, scores))), set(positive))
    if metrics is None:
        raise ValueError(f'No positive lines for pair {pair}')
    return dict(pair=pair, valid_lines=len(lines), positive_lines=len(set(lines)&set(positive)),
                first_positive_rank=round(1/metrics['mrr']))


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8*1024*1024), b''):
            digest.update(block)
    return digest.hexdigest()


def export(output, rows, model_name, extended=False):
    labels = {'attention': 'Attention Distance: incoming attention (SecureBERT2 classification)',
              'B': f'Safety-neuron adaptation B: All-neuron mean-difference ({model_name})',
              'E': f'Safety-neuron adaptation E: RBF-SVM ({model_name})'}
    if extended:
        labels.update(cls_classification='cls_classification',
                      cls_classification_with_rational='cls_classification_with_rational')
        labels['attention'] = 'attention distance (SecureBERT2)'
    stem = 'figure6' if extended else 'figure5'
    values, summary, ranks = [], [], []
    fig, ax = plt.subplots(figsize=(9, 5.5))
    for method, label in labels.items():
        samples = [r[method] for r in rows]
        points = curve(samples)
        values.extend(dict(method=method, label=label, **p) for p in points)
        ranks.extend(dict(method=method, **r) for r in samples)
        summary.append(dict(method=method, label=label, pairs=len(samples),
                            hit_at_1=np.mean([r['first_positive_rank']<=1 for r in samples]),
                            hit_at_5=np.mean([r['first_positive_rank']<=5 for r in samples]),
                            mrr=np.mean([1/r['first_positive_rank'] for r in samples])))
        ax.plot([p['fraction']*100 for p in points], [p['hit_rate']*100 for p in points],
                marker='o', markersize=4, label=label)
    ax.set(xlabel='Top-ranked valid lines inspected (%)', ylabel='Functions with at least one proxy-line hit (%)',
           title=f'Line-Level accuracy (N={len(rows)})',
           xlim=(10,100), ylim=(0,102))
    ax.grid(alpha=.25)
    ax.legend(fontsize=8, loc='lower right')
    fig.tight_layout()
    for suffix in ('png','pdf'):
        fig.savefig(output/f'{stem}.{suffix}', dpi=200)
    plt.close(fig)
    write_csv(output/f'{stem}.csv', values)
    write_csv(output/('figure6_report.csv' if extended else 'report.csv'), summary)
    write_csv(output/('figure6_ranks.csv' if extended else 'ranks.csv'), ranks)


def extend_comparison(output, classification_run, rationale_run):
    """Reuse saved first-hit ranks; no model forward pass or GPU is needed."""
    manifest = json.loads((output/'definition.json').read_text())
    rows = [json.loads(s) for s in (output/'progress.jsonl').read_text().splitlines()]
    indices = {r['pair'] for r in rows}
    if not rows or len(indices) != len(rows) or indices != set(manifest['indices']):
        raise ValueError('Incomplete or duplicate B/E comparison progress')
    sources = {}
    for method, run, mode in [('cls_classification', classification_run, 'classification'),
                              ('cls_classification_with_rational', rationale_run, 'rationale')]:
        meta = json.loads((run/'run.json').read_text())
        splits = json.loads((run/'splits.json').read_text())
        if (meta['dataset_sha256'] != manifest['dataset_sha256'] or
            meta['arguments']['mode'] != mode or not indices <= set(splits['test'])):
            raise ValueError(f'Dataset/mode/test split mismatch: {run}')
        with (run/'test/localization.csv').open() as stream:
            saved = list(csv.DictReader(stream))
        lookup = {int(r['pair']): r for r in saved}
        if len(lookup) != len(saved) or set(lookup) != indices:
            raise ValueError(f'Localization cohort mismatch: {run}')
        for row in rows:
            base = row['B']; item = lookup[row['pair']]
            expected = random_ranking_metrics(base['valid_lines'], base['positive_lines'])
            if any(not math.isclose(float(item['random_'+k]), expected[k], abs_tol=1e-9)
                   for k in ('hit_at_1', 'hit_at_5', 'mrr')):
                raise ValueError(f'Candidate/label count mismatch: pair {row["pair"]}')
            rr = float(item['mrr'])
            rank = round(1/rr) if rr > 0 else 0
            if not 1 <= rank <= base['valid_lines'] or not math.isclose(rr, 1/rank, abs_tol=1e-12):
                raise ValueError('Invalid reciprocal rank')
            row[method] = dict(base, first_positive_rank=rank)
        sources[method] = dict(run=str(run.resolve()), model_id=meta['model_id'],
                               localization_sha256=file_hash(run/'test/localization.csv'))
    export(output, rows, 'modernbert', extended=True)
    (output/'figure6_definition.json').write_text(json.dumps(dict(
        baseline_definition=manifest, baseline_progress_sha256=file_hash(output/'progress.jsonl'),
        added_sources=sources, rank_source='Exact first-hit rank recovered from saved reciprocal rank; no smoothing',
        random_curve_shown=False), indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--models', type=Path, default=NEURON_RUN/'inference_models.joblib')
    parser.add_argument('--attention-rescore', type=Path,
                        default=ROOT/'outputs/securebert2_classification/attention_rescore/test')
    parser.add_argument('--splits', type=Path,
                        default=ROOT/'outputs/pipeline_20261012_120515/modernbert_rationale/splits.json')
    parser.add_argument('--dataset', nargs='+', type=Path,
                        default=[ROOT.parent/'neuron/dataset/review/dataset.jsonl'])
    parser.add_argument('--output-dir', type=Path, default=ROOT/'outputs/neuron_comparison')
    parser.add_argument('--plot-only', action='store_true', help='Reuse completed B/E progress without loading models')
    parser.add_argument('--classification-run', type=Path, default=CLS_RUNS/'modernbert_classification')
    parser.add_argument('--rationale-run', type=Path, default=CLS_RUNS/'modernbert_rationale')
    parser.add_argument('--device', choices=['cpu','cuda','auto'], default='auto')
    parser.add_argument('--cpu-threads', type=int, default=4)
    args = parser.parse_args()
    if args.cpu_threads < 1:
        parser.error('--cpu-threads must be positive')
    if args.plot_only:
        extend_comparison(args.output_dir, args.classification_run, args.rationale_run)
        print(f'Figure 6 (PNG/PDF), curves and metrics (CSV): {args.output_dir}')
        return
    torch.set_num_threads(args.cpu_threads)
    records = [r for path in args.dataset for r in load_unified_records(path)]
    digest = fingerprint(records)
    attention_meta = json.loads((args.attention_rescore/'run.json').read_text())
    if attention_meta['dataset_sha256'] != digest or attention_meta['split'] != 'test':
        raise ValueError('Attention dataset/order or split mismatch')
    attention = [json.loads(s) for s in (args.attention_rescore/'progress.jsonl').read_text().splitlines()]
    indices = [r['pair'] for r in attention]
    if len(set(indices)) != len(indices) or set(indices) != set(attention_meta['indices']):
        raise ValueError('Attention rescore is incomplete or contains duplicate pairs')
    bundle = load_models(args.models)  # Only load your own trusted joblib files.
    metadata = bundle['metadata']; extraction = metadata['extraction']
    splits = json.loads(args.splits.read_text())
    if (fingerprint(splits) != extraction['splits'] or
        fingerprint([records[i] for i in splits['train']]) != extraction['train_records'] or
        not set(indices) <= set(splits['test'])):
        raise ValueError('Neuron dataset/order/splits do not match the attention test cohort')
    methods = {name: bundle['models'][name] for name in ('B','E')}
    model_name = metadata['training']['model']
    output = args.output_dir; output.mkdir(parents=True, exist_ok=True)
    manifest = dict(version=1, dataset_sha256=digest, models_sha256=file_hash(args.models),
                    attention_progress_sha256=file_hash(args.attention_rescore/'progress.jsonl'),
                    selection='Previously selected by validation; no fitting or test selection',
                    selected_layers={m: int(v['layer']) for m,v in methods.items()},
                    metric='Hit@ceil(fraction * valid lines), >=1 changed/deleted proxy line',
                    ties='Nonpositive lines first on equal scores; E uses raw margins to avoid tanh saturation',
                    caveats=['B/E are adaptations, not original paper methods',
                             'Different encoders/training objectives; not a controlled ablation',
                             'Incoming attention only; no CFG/basic-block evaluation'],
                    indices=indices)
    manifest_path = output/'definition.json'
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError('Output belongs to different inputs; choose a new --output-dir')
    manifest_path.write_text(json.dumps(manifest, indent=2))
    progress = output/'progress.jsonl'
    rows = [json.loads(s) for s in progress.read_text().splitlines()] if progress.exists() else []
    done = {r['pair'] for r in rows}
    if len(done)!=len(rows) or not done<=set(indices):
        raise ValueError('Invalid saved progress')
    pending = [r for r in attention if r['pair'] not in done]
    if pending:
        device = ('cuda' if torch.cuda.is_available() else 'cpu') if args.device=='auto' else args.device
        limit = extraction['max_length']; revision = extraction['revision']
        tokenizer, _ = load_tokenizer(model_name, revision, limit)
        model = load_encoder(device, model_name, revision, limit)
        model.config.reference_compile = False
        extractors = {layer: ActivationExtractor(model, layer) for layer in {v['layer'] for v in methods.values()}}
        try:
            with progress.open('a') as stream, torch.inference_mode(), threadpool_limits(limits=args.cpu_threads):
                for source in tqdm(pending, desc='Selected B/E test', initial=len(done), total=len(indices)):
                    i = source['pair']; before, after = [s['code'] for s in records[i]]
                    inputs, mapping, valid, truncated = prepare_code_input(before, tokenizer, limit)
                    positive = changed_vulnerable_lines(before, after)&valid
                    if truncated or valid != set(source['lines']) or positive != set(source['positive']):
                        raise ValueError(f'Candidate/label mismatch for pair {i}')
                    for ext in extractors.values(): ext.clear()
                    model(**{k:v.to(device) for k,v in inputs.items()})
                    row = dict(pair=i, attention=rank_row(i, source['lines'], source['positive'], source['incoming']))
                    lines = sorted(valid)
                    for name, info in methods.items():
                        acts = get_line_level_activations(extractors[info['layer']].activation[0], mapping, len(before.split('\n')))
                        neurons = info['target_neurons']
                        reps = acts[lines][:, neurons] @ info['down_proj'][neurons]
                        if name=='E':
                            scores = info['estimator'].decision_function(reps.numpy())
                        else:
                            scores = score_target_line(reps, info['d_v']).numpy()
                        row[name] = rank_row(i, lines, positive, scores)
                    stream.write(json.dumps(row)+'\n'); stream.flush(); rows.append(row)
        finally:
            for ext in extractors.values(): ext.remove_hooks()
    if not rows:
        raise ValueError('Empty cohort')
    export(output, rows, model_name)
    extend_comparison(output, args.classification_run, args.rationale_run)
    print(f'Figure 5 (PNG/PDF), curves and metrics (CSV): {output}')


if __name__=='__main__':
    main()

"""Unfine-tuned Eq.4 adaptation, paired to an existing experiment's held-out split."""
import argparse
import csv
import gc
import json
from pathlib import Path
import torch
from tqdm import tqdm
from transformers import AutoTokenizer
from .model_config import ATTENTION_MODELS, load_attention_encoder, load_tokenizer, MAX_LENGTH
from .training_artifacts import load_models, fingerprint
from .splits import load_unified_records, split_pairs
from .mapper import prepare_code_input, get_line_level_activations
from .hook_utils import ActivationExtractor
from .direction import score_target_line
from .evaluation import changed_vulnerable_lines, localization_metrics, random_ranking_metrics
from .attention_scoring import attention_line_scores


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--dataset', nargs='+', required=True)
    cli.add_argument('--reference-models', required=True)
    cli.add_argument('--model', nargs='+', choices=list(ATTENTION_MODELS), default=list(ATTENTION_MODELS))
    cli.add_argument('--output-dir', type=Path, required=True)
    cli.add_argument('--cpu-threads', type=int, default=4)
    args = cli.parse_args()
    if args.cpu_threads < 1:
        cli.error('--cpu-threads must be positive')
    torch.set_num_threads(args.cpu_threads)
    reference = load_models(args.reference_models)
    meta = reference['metadata']
    settings = meta['training']
    records = [pair for path in args.dataset for pair in load_unified_records(path, settings.get('cwe'))]
    ref_tokenizer, _ = load_tokenizer(settings['model'], meta['extraction']['revision'])
    eligible = [i for i, pair in enumerate(tqdm(records, desc='Verify original split'))
                if all(len(ref_tokenizer(side['code'], truncation=False, verbose=False)['input_ids']) <= MAX_LENGTH for side in pair)]
    splits = split_pairs(records, eligible, settings['split_seed'])
    if fingerprint(splits) != meta['extraction']['splits'] or fingerprint([records[i] for i in splits['train']]) != meta['extraction']['train_records']:
        raise ValueError('Dataset/order/split mismatch; refusing a different test set')
    tokenizers = {name: AutoTokenizer.from_pretrained(mid, use_fast=True) for name, (mid, _) in ATTENTION_MODELS.items()}
    plans = {name: [] for name in ATTENTION_MODELS}
    reference_lines = {}
    counts = {name: dict(total_test_pairs=len(splits['test']), no_changed_lines=0, overlength=0,
                        no_valid_labels=0, different_candidate_lines=0) for name in ATTENTION_MODELS}
    for i in tqdm(splits['test'], desc='Prepare matched cohorts'):
        before, after = (side['code'] for side in records[i])
        labels = changed_vulnerable_lines(before, after)
        ref_valid = prepare_code_input(before, ref_tokenizer)[2] if labels else set()
        reference_lines[i] = ref_valid
        for name, tokenizer in tokenizers.items():
            c = counts[name]
            if not labels:
                c['no_changed_lines'] += 1
                continue
            limit = ATTENTION_MODELS[name][1]
            if any(len(tokenizer(code, truncation=False, verbose=False)['input_ids']) > limit for code in (before, after)):
                c['overlength'] += 1
                continue
            valid = prepare_code_input(before, tokenizer, limit)[2]
            if valid != ref_valid:
                c['different_candidate_lines'] += 1
                continue
            if not labels & valid:
                c['no_valid_labels'] += 1
                continue
            plans[name].append(i)
    common = set.intersection(*(set(indices) for indices in plans.values()))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest = dict(status='unfine_tuned_attention_line_score_adaptation_not_full_Attention_Distance',
                    dataset_sha256=fingerprint(records), reference_cache_key=meta['cache_key'],
                    model_limits={name: limit for name, (_,limit) in ATTENTION_MODELS.items()},
                    plans=plans, common_indices=sorted(common), counts=counts,
                    reduction='sum layers / mean heads / sum incoming queries / sum line tokens; special queries included; no padding',
                    pretrained_data_overlap='not audited', score_version=1)
    manifest_path = args.output_dir / 'manifest.json'
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError('Existing output belongs to a different experiment')
    manifest_path.write_text(json.dumps(manifest, indent=2))
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f'Device={device}; native cohorts={ {k:len(v) for k,v in plans.items()} }; common={len(common)}', flush=True)
    def summarize():
        rows = []
        for name in ATTENTION_MODELS:
            path = args.output_dir / f'{name}.progress.jsonl'
            if not path.exists():
                continue
            results = [json.loads(line) for line in path.read_text().splitlines()]
            for scope in ('native', 'common'):
                selected = [r for r in results if scope == 'native' or r['index'] in common]
                total = len(plans[name]) if scope == 'native' else len(common)
                for method in ('attention', 'random', 'B'):
                    values = [r[method] for r in selected if method in r]
                    if not values:
                        continue
                    rows.append(dict(model=name, method=method, cohort=scope, completed=len(values), expected=total,
                                     complete=len(values)==total,
                                     **{k:sum(x[k] for x in values)/len(values) for k in values[0]}))
        if rows:
            (args.output_dir / 'report.json').write_text(json.dumps(dict(
                status=manifest['status'], reduction=manifest['reduction'], counts=counts,
                common_test_pairs=len(common), results=rows), indent=2))
            with (args.output_dir / 'report.csv').open('w', newline='') as stream:
                writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    for name in args.model:
        path = args.output_dir / f'{name}.progress.jsonl'
        done = {json.loads(line)['index'] for line in path.read_text().splitlines()} if path.exists() else set()
        pending = [i for i in plans[name] if i not in done]
        if not pending:
            summarize(); continue
        tokenizer, model, limit = load_attention_encoder(name, device)
        revision = getattr(model.config, '_commit_hash', None)
        revision_path = args.output_dir / f'{name}.revision.json'
        if revision_path.exists() and json.loads(revision_path.read_text()) != revision:
            raise ValueError('Model revision changed during resume')
        revision_path.write_text(json.dumps(revision))
        b_info = reference['models']['B'] if name == settings['model'] and revision == meta['extraction']['revision'] else None
        extractor = ActivationExtractor(model, b_info['layer']) if b_info else None
        try:
            with path.open('a') as stream:
                for i in tqdm(pending, desc=f'{name} attention', initial=len(done), total=len(plans[name])):
                    before, after = (side['code'] for side in records[i])
                    labels = changed_vulnerable_lines(before, after)
                    scores = attention_line_scores(before, model, tokenizer, limit)
                    row = dict(index=i, attention=localization_metrics(scores, labels),
                               random=random_ranking_metrics(len(scores), len(labels & scores.keys())))
                    if extractor:
                        _, mapping, _, _ = prepare_code_input(before, tokenizer, limit)
                        acts = get_line_level_activations(extractor.activation[0], mapping, len(before.split('\n')))
                        indices = b_info['target_neurons']
                        values = score_target_line(acts[:, indices] @ b_info['down_proj'][indices], b_info['d_v'])
                        row['B'] = localization_metrics({q:float(values[q]) for q in scores}, labels)
                        extractor.clear()
                    stream.write(json.dumps(row)+'\n'); stream.flush()
                    if (len(done)+1) % 25 == 0:
                        summarize()
                    done.add(i)
        finally:
            if extractor:
                extractor.remove_hooks()
            summarize()
            del model
            gc.collect()
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
    print(f'Results: {args.output_dir / "report.csv"}', flush=True)

"""Frozen encoder function-level linear probe: before vs after, not verified safety."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import numpy as np
import torch
from tqdm import tqdm
from core.model_config import MODELS, MAX_LENGTH, load_tokenizer, load_encoder
from core.splits import split_pairs

POOLINGS = ('cls', 'mean', 'last')


def pool_hidden(hidden, attention_mask, special_tokens_mask, input_ids, cls_token_id):
    valid = attention_mask.bool() & ~special_tokens_mask.bool()
    if not valid.any():
        raise ValueError('No code tokens')
    if cls_token_id is None:
        raise ValueError('CLS token missing')
    cls = (input_ids == cls_token_id) & attention_mask.bool()
    if not cls.any():
        raise ValueError('CLS token missing')
    return {'cls': hidden[cls.nonzero()[0, 0]],
            'mean': hidden[valid].mean(0),
            'last': hidden[valid.nonzero()[-1, 0]]}


def load_records(paths, cwes):
    records, provenance = [], []
    files = sorted({f.resolve() for p in paths for f in
                    (sorted(p.glob('*.jsonl')) if p.is_dir() else [p])})
    if not files:
        raise ValueError('No input JSONL files')
    for path in files:
        provenance.append({'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        with path.open() as stream:
            for line_no, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                row = json.loads(line)
                meta = {k: v for k, v in row.items() if k not in ('func_before', 'func_after', 'metadata')}
                meta.update(row.get('metadata') or {})
                labels = meta.get('cwe_ids') or []
                if isinstance(labels, str):
                    labels = [labels]
                labels = list(labels) + [meta.get('CWE ID'), meta.get('cwe_id')]
                if cwes and not set(cwes).intersection(labels):
                    continue
                sides = []
                for key in ('func_before', 'func_after'):
                    if not isinstance(row.get(key), str):
                        raise ValueError(f'{path}:{line_no}: missing string {key}')
                    sides.append(dict(id=row.get('pair_id'), code=row[key], metadata=meta,
                                      source_file=str(path), source_line=line_no))
                records.append(tuple(sides))
    return records, provenance


def metrics(scores):
    from sklearn.metrics import roc_auc_score, balanced_accuracy_score
    labels = np.tile([1, 0], len(scores))
    return {'auroc': float(roc_auc_score(labels, scores.reshape(-1))),
            'balanced_accuracy': float(balanced_accuracy_score(labels, (scores.reshape(-1) >= 0).astype(int))),
            'pairwise_accuracy': float(np.mean((scores[:, 0] > scores[:, 1]) +
                                               .5 * (scores[:, 0] == scores[:, 1])))}


def confidence_intervals(scores, groups, repeats, seed):
    # Resample connected CVE/commit/exact-code groups, not independent functions.
    if len(groups) < 2 or repeats == 0:
        return None
    rng = np.random.default_rng(seed)
    draws = []
    for _ in range(repeats):
        ids = np.concatenate([groups[i] for i in rng.integers(len(groups), size=len(groups))])
        draws.append(metrics(scores[ids]))
    return {k: np.quantile([d[k] for d in draws], [.025, .975]).tolist() for k in draws[0]}


def connected_groups(records, indices):
    # Same linkage as the shared splitter, retained for clustered uncertainty estimates.
    parent = {i: i for i in indices}
    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    seen = {}
    for i in indices:
        keys = []
        for r in records[i]:
            m = r['metadata']
            cves = m.get('cve_ids') or []
            if isinstance(cves, str):
                cves = [cves]
            keys += [('cve', c) for c in list(cves) + [m.get('CVE ID'), m.get('cve_id')] if c]
            for kind, value in [('id', r.get('id')), ('commit', m.get('commit_id') or m.get('hash')),
                                ('code', r['code'].strip())]:
                if value:
                    keys.append((kind, value))
        for key in keys:
            if key in seen:
                parent[root(i)] = root(seen[key])
            else:
                seen[key] = i
    groups = {}
    for position, i in enumerate(indices):
        groups.setdefault(root(i), []).append(position)
    return list(groups.values())


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--dataset', type=Path, nargs='+', default=[Path(__file__).resolve().parent/'dataset/source'])
    cli.add_argument('--cwe', nargs='+')
    cli.add_argument('--output', type=Path, default=Path('function_probe_report.json'))
    cli.add_argument('--seed', type=int, default=42)
    cli.add_argument('--model', choices=MODELS, default='modernbert')
    cli.add_argument('--max-length', type=int, default=MAX_LENGTH,
                     help='Maximum tokens per complete function, including special tokens (default: 8192)')
    cli.add_argument('--revision', default='main', help='Revision for the selected model')
    cli.add_argument('--c-values', type=float, nargs='+', default=[.01, .1, 1., 10.])
    cli.add_argument('--bootstrap', type=int, default=1000)
    args = cli.parse_args()
    if args.output.exists():
        cli.error('Output exists; choose a new --output')
    if args.bootstrap < 0 or any(not np.isfinite(c) or c <= 0 for c in args.c_values):
        cli.error('C values must be finite positive numbers; bootstrap must be nonnegative')
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import LogisticRegression
    records, sources = load_records(args.dataset, args.cwe)
    model_id = MODELS[args.model]
    max_length = args.max_length
    tokenizer, revision = load_tokenizer(args.model, args.revision, max_length)
    retained, counts = [], Counter(total_pairs=len(records))
    for i, pair in enumerate(tqdm(records, desc='Checking complete functions')):
        if any(not r['code'].strip() for r in pair):
            counts['empty'] += 1
        elif pair[0]['code'].strip() == pair[1]['code'].strip():
            counts['identical'] += 1
        elif any(len(tokenizer(r['code'], truncation=False, verbose=False)['input_ids']) > max_length for r in pair):
            counts['overlength'] += 1
        else:
            retained.append(i)
    print('Pair filtering:', dict(counts, retained=len(retained)), flush=True)
    splits = split_pairs(records, retained, seed=args.seed)
    print('Splits:', {k: len(v) for k, v in splits.items()}, flush=True)
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    model = load_encoder(device, args.model, revision, max_length)
    features = {p: {} for p in POOLINGS}
    with torch.inference_mode():
        for i in tqdm(retained, desc='Extracting frozen function representations'):
            pooled_pair = []
            for record in records[i]:
                inputs = tokenizer(record['code'], return_tensors='pt', truncation=False,
                                   return_special_tokens_mask=True)
                special = inputs.pop('special_tokens_mask').to(device)[0]
                inputs = {k: v.to(device) for k, v in inputs.items()}
                hidden = model(**inputs).last_hidden_state[0].float()
                pooled_pair.append(pool_hidden(hidden, inputs['attention_mask'][0], special,
                                               inputs['input_ids'][0], tokenizer.cls_token_id))
            for p in POOLINGS:
                features[p][i] = np.stack([x[p].cpu().numpy() for x in pooled_pair])
    del model
    if device == 'cuda':
        torch.cuda.empty_cache()
    validation, best = [], None
    for p in POOLINGS:
        train = np.stack([features[p][i] for i in splits['train']])
        val = np.stack([features[p][i] for i in splits['validation']])
        for c in sorted(set(args.c_values)):
            probe = make_pipeline(StandardScaler(), LogisticRegression(C=c, max_iter=3000, random_state=args.seed))
            probe.fit(train.reshape(-1, train.shape[-1]), np.tile([1, 0], len(train)))
            scores = probe.decision_function(val.reshape(-1, val.shape[-1])).reshape(-1, 2)
            result = dict(pooling=p, C=c, **metrics(scores))
            validation.append(result)
            print('Validation:', result, flush=True)
            # Strict improvement: pooling declaration order then smaller C breaks ties.
            if best is None or result['auroc'] > best[0]['auroc']:
                best = (result, probe)
    selected, probe = best
    test = np.stack([features[selected['pooling']][i] for i in splits['test']])
    scores = probe.decision_function(test.reshape(-1, test.shape[-1])).reshape(-1, 2)
    groups = connected_groups(records, splits['test'])
    report = dict(model=model_id, revision=revision, seed=args.seed, max_length=max_length,
                  sources=sources, cwe_filter=args.cwe, filtering=dict(counts, retained=len(retained)),
                  label_policy='before=1, after=0; not verified vulnerable/safe labels',
                  selection='validation AUROC; ties: cls, mean, last then smaller C; no train+validation refit',
                  splits=splits, validation=validation, selected=selected,
                  test=dict(metrics=metrics(scores), groups=len(groups),
                            bootstrap_95_ci=confidence_intervals(scores, groups, args.bootstrap, args.seed),
                            predictions=[dict(index=i, pair_id=records[i][0]['id'],
                                              source_file=records[i][0]['source_file'],
                                              source_line=records[i][0]['source_line'],
                                              before_score=float(s[0]), after_score=float(s[1]))
                                         for i, s in zip(splits['test'], scores)]))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
    print('Test:', report['test']['metrics'])
    print('Saved:', args.output)


if __name__ == '__main__':
    main()

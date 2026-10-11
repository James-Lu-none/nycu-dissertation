"""Reuse the existing grouped split and token/line mapping definitions."""
import hashlib
import json
from pathlib import Path
import random
import sys

NEURON = Path(__file__).resolve().parents[1] / 'neuron'
sys.path.insert(0, str(NEURON))
from core.splits import load_unified_records, split_pairs
from core.mapper import map_tokens_to_lines
from core.evaluation import changed_vulnerable_lines
from core.training_artifacts import fingerprint, load_models


def prepare(args, tokenizer):
    records = [p for path in args.dataset for p in load_unified_records(path)]
    if args.reference_models:
        from transformers import AutoTokenizer
        reference = load_models(args.reference_models)['metadata']
        if reference['training'].get('cwe'):
            raise ValueError('Use an ALL reference experiment')
        from core.model_config import MODELS
        ref_tok = AutoTokenizer.from_pretrained(MODELS[reference['training']['model']], revision=reference['extraction']['revision'])
        limit = reference['extraction']['max_length']
        eligible = [i for i,p in enumerate(records) if all(len(ref_tok(s['code'], truncation=False, verbose=False)['input_ids']) <= limit for s in p)]
        splits = split_pairs(records, eligible, reference['training']['split_seed'])
        if fingerprint(splits) != reference['extraction']['splits'] or fingerprint([records[i] for i in splits['train']]) != reference['extraction']['train_records']:
            raise ValueError('Reference dataset/order/split mismatch')
    else:
        # Split before model-specific filtering, so a model cannot move pairs across splits.
        splits = split_pairs(records, range(len(records)), args.seed)
    examples, counts = {}, {}
    from tqdm import tqdm
    for split, indices in splits.items():
        rows = []
        count = dict(total_pairs=len(indices), overlength=0, unchanged=0, retained_pairs=0, missing_rationale=0)
        for i in tqdm(indices, desc=f'Tokenize {split}'):
            pair = records[i]
            if pair[0]['code'].strip() == pair[1]['code'].strip():
                count['unchanged'] += 1
                continue
            encoded = [tokenizer(s['code'], return_offsets_mapping=True, truncation=False, verbose=False) for s in pair]
            if any(len(e['input_ids']) > args.max_length for e in encoded):
                count['overlength'] += 1
                continue
            changed = changed_vulnerable_lines(pair[0]['code'], pair[1]['code'])
            for side, (source, encoding) in enumerate(zip(pair, encoded)):
                mapping = map_tokens_to_lines(source['code'], encoding.pop('offset_mapping'))
                lines = sorted(set(mapping.values()) - {-1})
                compact = {q:j for j,q in enumerate(lines)}
                positives = [compact[q] for q in lines if q in changed] if side == 0 else []
                seed = int(hashlib.sha256(f'{args.seed}:{i}'.encode()).hexdigest()[:16], 16)
                # Same positive-line count; prefer non-rationale lines, fill if necessary.
                rng = random.Random(seed)
                negative = [j for j in range(len(lines)) if j not in positives]
                rng.shuffle(negative)
                random_lines = negative[:len(positives)]
                if len(random_lines) < len(positives):
                    random_lines += rng.sample(positives, len(positives)-len(random_lines))
                rows.append(dict(pair=i, label=1-side, inputs=dict(encoding),
                                 line_ids=[compact.get(mapping[t], -1) for t in range(len(mapping))],
                                 positive=positives, random=sorted(random_lines), source_lines=lines))
                if side == 0 and not positives:
                    count['missing_rationale'] += 1
            count['retained_pairs'] += 1
        examples[split], counts[split] = rows, count
    return examples, dict(dataset_sha256=fingerprint(records), splits=splits, counts=counts)


def collate(rows, tokenizer):
    inputs = tokenizer.pad([r['inputs'] for r in rows], padding=True, return_tensors='pt')
    return dict(inputs), rows

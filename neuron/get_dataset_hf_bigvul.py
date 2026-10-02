"""Export BigVul C function-pair candidates with their original metadata."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

DATASET_ID = 'bstee615/bigvul'
DEFAULT_OUTPUT = Path(__file__).resolve().parent / 'dataset/source/bigvul.jsonl'


def convert_row(row, index, revision, split):
    if str(row.get('lang') or '').strip().upper() != 'C':
        return None, 'excluded_non_c'
    before, after = row.get('func_before'), row.get('func_after')
    if any(not isinstance(code, str) or not code.strip() for code in (before, after)):
        return None, 'excluded_empty_or_invalid_code'
    if before.strip() == after.strip():
        return None, 'excluded_identical_code'
    metadata = {k: v for k, v in row.items() if k not in ('func_before', 'func_after')}
    identity = json.dumps([DATASET_ID, revision, split, index], ensure_ascii=False)
    pair_id = hashlib.sha256(identity.encode()).hexdigest()
    return {
        'pair_id': pair_id,
        'func_before': before,
        'func_after': after,
        'metadata': metadata,
        'source': {'dataset': DATASET_ID, 'revision': revision, 'split': split, 'row_index': index},
    }, 'exported_pairs'


def export_rows(rows, output, revision, split):
    output = Path(output)
    report_path = output.with_suffix('.report.json')
    if output.exists() or report_path.exists():
        raise FileExistsError(f'Output/report already exists: {output}; choose another --output')
    output.parent.mkdir(parents=True, exist_ok=True)
    counts = Counter()
    from tqdm import tqdm
    # Exclusive creation prevents silently overwriting previous datasets.
    with output.open('x', encoding='utf-8') as stream:
        for index, row in enumerate(tqdm(rows, desc='Exporting BigVul pairs', unit='row')):
            counts['total_rows'] += 1
            pair, reason = convert_row(row, index, revision, split)
            counts[reason] += 1
            if pair is not None:
                stream.write(json.dumps(pair, ensure_ascii=False) + '\n')
    report = {
        'dataset': DATASET_ID, 'revision': revision, 'split': split,
        'language_filter': 'C (source label)', 'cwe_filter': None,
        'counts': dict(counts),
        'notes': ['All original non-code fields preserved in metadata.',
                  'No length filter, parser validation or LLM review applied.',
                  'Duplicate source records retained; pair IDs identify revision/split/row.',
                  'These are candidate pairs, not verified vulnerability labels.'],
    }
    with report_path.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f'Pairs: {output}\nReport: {report_path}')
    return report


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    cli.add_argument('--revision', default='main', help='Resolved to a fixed HF commit before downloading')
    cli.add_argument('--split', default='train')
    args = cli.parse_args()
    if args.output.exists() or args.output.with_suffix('.report.json').exists():
        cli.error('Output/report already exists; choose another --output')
    from datasets import load_dataset
    from huggingface_hub import HfApi
    revision = HfApi().dataset_info(DATASET_ID, revision=args.revision).sha
    print(f'Loading {DATASET_ID} at {revision}, split={args.split}', flush=True)
    rows = load_dataset(DATASET_ID, revision=revision, split=args.split)
    export_rows(rows, args.output, revision, args.split)


if __name__ == '__main__':
    main()

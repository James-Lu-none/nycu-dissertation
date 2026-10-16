"""Plot incoming-attention scores for the exact examples in a reference line_scores.csv."""
import argparse
import csv
import json
import html
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent


def export_code_scores(output, examples, selected, args, reference_meta):
    from data import load_unified_records, fingerprint
    records = load_unified_records(args.dataset)
    if fingerprint(records) != reference_meta['dataset_sha256']:
        raise ValueError('Source code dataset/order mismatch')
    run = args.classification.parent.parent
    meta = json.loads((run/'run.json').read_text())
    if meta['dataset_sha256'] != reference_meta['dataset_sha256'] or meta['arguments']['mode'] != 'classification':
        raise ValueError('Classification dataset/mode mismatch')
    if reference_meta['arguments']['mode'] != 'rationale' or args.classification.parent.name != args.reference.parent.name:
        raise ValueError('Rationale mode/split mismatch')
    split = args.reference.parent.name
    for directory in (run, args.reference.parent.parent):
        if not set(examples) <= set(json.loads((directory/'splits.json').read_text())[split]):
            raise ValueError('Example is not in the requested split')
    classification = {}
    with args.classification.open() as stream:
        for row in csv.DictReader(stream):
            key = (int(row['pair']), int(row['line']))
            if key in classification:
                raise ValueError('Duplicate classification line')
            classification[key] = row
    description = (
        'A: Attention Distance (ICSE 2026), incoming-attention scoring adaptation; SecureBERT2 classification.\n'
        'B: cls-classification; ModernBERT.\n'
        'C: cls-classification_with_rational; ModernBERT.\n'
        'A is normalized by its valid-line sum; B/C retain saved normalized scores. Not vulnerability probabilities.\n'
        '* = changed/deleted proxy line. Unscored lines use NA. A does not include CFG/basic-block processing.\n')
    text = [description]
    page = ['<!doctype html><meta charset="utf-8"><title>Test sample line scores</title>',
            '<style>body{font-family:system-ui;margin:24px}table{border-collapse:collapse;margin-bottom:32px}th,td{padding:4px 10px;border-bottom:1px solid #ddd;text-align:right}td.code{text-align:left;white-space:pre;font-family:monospace}.positive{background:#ffe5df}thead{background:#eee}</style>',
            '<h1>Test sample line scores</h1><pre>'+html.escape(description)+'</pre>']
    rows = []
    for pair, reference in examples.items():
        source = selected[pair]
        raw = np.asarray(source['incoming'], dtype=float)
        a = dict(zip([q+1 for q in source['lines']], raw/raw.sum()))
        c = {int(r['line']): r for r in reference}
        if {q for p,q in classification if p == pair} != set(c):
            raise ValueError(f'Classification candidate-line mismatch: {pair}')
        source_code = records[pair][0]['code']
        code_dir = output/'code_only'
        code_dir.mkdir(exist_ok=True)
        (code_dir/f'pair_{pair}.txt').write_text(source_code)
        code = source_code.split('\n')
        text += [f'\nPair {pair} — vulnerable function\n', 'Line |     A      |     B      |     C      | Proxy | Code\n']
        page += [f'<h2>Pair {pair} — vulnerable function</h2><table><thead><tr><th>Line</th><th>A</th><th>B</th><th>C</th><th>Proxy</th><th>Code</th></tr></thead><tbody>']
        for line, content in enumerate(code, 1):
            scores = ['NA']*3; positive = None; b_score = c_score = None
            if line in c:
                b = classification[pair,line]
                positive = int(c[line]['proxy_positive'])
                if int(b['proxy_positive']) != positive:
                    raise ValueError(f'Label mismatch: {pair}:{line}')
                b_score, c_score = float(b['score']), float(c[line]['score'])
                if not np.isfinite([b_score, c_score]).all():
                    raise ValueError('Nonfinite CLS scores')
                scores = [f'{s:.6f}' for s in (a[line], b_score, c_score)]
            marker = '*' if positive else ''
            text.append(f'{line:4d} | {scores[0]:>10} | {scores[1]:>10} | {scores[2]:>10} | {marker:^5} | {content}\n')
            page.append('<tr'+(' class="positive"' if positive else '')+'>'+''.join(f'<td>{s}</td>' for s in [str(line),*scores,marker])+f'<td class="code">{html.escape(content)}</td></tr>')
            rows.append(dict(pair=pair,line=line,A=a.get(line),B=b_score,C=c_score,proxy_positive=positive,code=content))
        page.append('</tbody></table>')
    (output/'code_scores.txt').write_text(''.join(text))
    (output/'code_scores.html').write_text('\n'.join(page))
    with (output/'code_scores.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    (output/'code_scores_definition.json').write_text(json.dumps(dict(
        dataset=str(args.dataset.resolve()), dataset_sha256=reference_meta['dataset_sha256'],
        classification=str(args.classification.resolve()), rationale=str(args.reference.resolve()),
        incoming=str(args.rescore.resolve()), pairs=list(examples), definition=description), indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, default=ROOT/'outputs/pipeline_20261012_231316/modernbert_rationale/test/line_scores.csv')
    parser.add_argument('--rescore', type=Path, default=ROOT/'outputs/pipeline_20261011_231355/securebert2_classification/attention_rescore/test')
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--classification', type=Path, default=ROOT/'outputs/pipeline_20261012_231316/modernbert_classification/test/line_scores.csv')
    parser.add_argument('--dataset', type=Path, default=ROOT.parent/'neuron/dataset/review/dataset.jsonl')
    args = parser.parse_args()
    reference_meta = json.loads((args.reference.parent.parent/'run.json').read_text())
    source_meta = json.loads((args.rescore/'run.json').read_text())
    if reference_meta['dataset_sha256'] != source_meta['dataset_sha256'] or source_meta['split'] != args.reference.parent.name:
        raise ValueError('Dataset/split mismatch')
    examples = {}
    with args.reference.open() as stream:
        for row in csv.DictReader(stream):
            examples.setdefault(int(row['pair']), []).append(row)
    selected = {}
    with (args.rescore/'progress.jsonl').open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['pair'] in examples:
                if row['pair'] in selected:
                    raise ValueError('Duplicate pair')
                selected[row['pair']] = row
    if not examples or set(selected) != set(examples):
        raise ValueError('Missing reference examples in rescore')
    fig, axes = plt.subplots(len(examples), 1, figsize=(11, 2.5*len(examples)), squeeze=False)
    exported = []
    for ax, (pair, reference) in zip(axes[:, 0], examples.items()):
        row = selected[pair]
        lines = [q+1 for q in row['lines']]
        positive = [int(q in row['positive']) for q in row['lines']]
        if lines != [int(r['line']) for r in reference] or positive != [int(r['proxy_positive']) for r in reference]:
            raise ValueError(f'Candidate lines/labels mismatch: {pair}')
        raw = np.asarray(row['incoming'], dtype=float)
        if len(raw) != len(lines) or not np.isfinite(raw).all() or (raw < 0).any() or raw.sum() <= 0:
            raise ValueError(f'Invalid incoming scores: {pair}')
        scores = raw/raw.sum()  # Display-only normalization; line ranking is unchanged.
        ax.bar(lines, scores, color=['tomato' if p else 'steelblue' for p in positive])
        ax.set(title=f'Pair {pair}: attention distance; red = changed/deleted proxy',
               xlabel='Source line (1-based)', ylabel='Normalized line score')
        exported.extend(dict(pair=pair, line=q, score=float(s), raw_score=float(v), proxy_positive=p)
                        for q, s, v, p in zip(lines, scores, raw, positive))
    fig.tight_layout()
    output = args.output_dir or args.rescore/'line_examples'
    output.mkdir(parents=True, exist_ok=True)
    for suffix in ('png', 'pdf'):
        fig.savefig(output/f'line_scores.{suffix}', dpi=180)
    plt.close(fig)
    with (output/'line_scores.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(exported[0]))
        writer.writeheader(); writer.writerows(exported)
    (output/'definition.json').write_text(json.dumps(dict(
        reference=str(args.reference.resolve()), source=str(args.rescore.resolve()),
        source_metadata=source_meta, pairs=list(examples),
        normalization='Incoming score divided by sum over valid lines within each function; not vulnerability probability'), indent=2))
    export_code_scores(output, examples, selected, args, reference_meta)
    print(f'Saved {len(examples)} matched examples: {output}')


if __name__ == '__main__':
    main()

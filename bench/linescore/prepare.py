"""Export completed model scores to integer DAFL weights; no inference required."""
import argparse
import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1]
METHODS = {'attention': 'attention_distance', 'rationale': 'rationale'}
FALLBACK = {'parse_error', 'unresolved_function', 'ambiguous_function', 'overlength', 'no_valid_tokens'}


def convert(project, scores):
    original = (project / 'slice_dfg.txt').read_text()
    nodes = []
    for line in original.splitlines():
        if line.strip():
            weight, location = line.split()
            weight = int(weight)
            if weight < 0:
                raise ValueError('Negative DAFL weight')
            nodes.append((weight, location))
    with scores.open() as stream:
        rows = list(csv.DictReader(stream))
    outputs = {}; reports = {}
    for suffix, method in METHODS.items():
        index = {}
        for row in rows:
            if row['method'] != method:
                continue
            location = f"{row['requested_file']}:{row['line']}"
            if location in index:
                raise ValueError(f'Duplicate score: {method} {location}')
            index[location] = row
        if set(index) != {loc for _, loc in nodes}:
            raise ValueError(f'{project.name}: {method} score locations do not match slice')
        counts = Counter(); lines = []
        for weight, location in nodes:
            row = index[location]; status = row['status']; counts[status] += 1
            if int(row['original_dfg_value']) != weight:
                raise ValueError(f'Stale DFG weight: {location}')
            if status == 'scored':
                percentile = float(row['function_percentile'])
                if not math.isfinite(percentile) or not 0 <= percentile <= 1:
                    raise ValueError(f'Invalid percentile: {location}')
                factor = 0.5 + percentile
            elif status in FALLBACK:
                factor = 1.0
            else:
                raise ValueError(f'{project.name}: {method} {location}: {status}; finish scoring first')
            value = math.floor(weight * 1000 * factor + 0.5)
            if value > 2**31 - 1:
                raise ValueError('Weight exceeds DAFL stoi range')
            lines.append(f'{value} {location}\n')
        if not counts['scored']:
            raise ValueError(f'{project.name}: no scored lines for {method}')
        outputs[suffix] = ''.join(lines); reports[suffix] = dict(counts)
    # Validate both methods before writing either file.
    dest = project / 'linescore'; dest.mkdir(exist_ok=True)
    for suffix, contents in outputs.items():
        (dest / f'slice_{suffix}.txt').write_text(contents)
    report = dict(formula='round_half_up(original * 1000 * (0.5 + function_percentile))',
                  fallback='original * 1000; no nodes removed', counts=reports,
                  scores_sha256=hashlib.sha256(scores.read_bytes()).hexdigest(),
                  slice_sha256=hashlib.sha256(original.encode()).hexdigest(),
                  score_source=str(scores.resolve()))
    (dest / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scores', type=Path, default=BENCH.parent/'attention/outputs/bench_scores')
    parser.add_argument('--benchmark', help='One benchmark directory name; default: all')
    args = parser.parse_args()
    projects = [BENCH/args.benchmark] if args.benchmark else sorted(p.parent for p in BENCH.glob('*/Dockerfile.linescore'))
    failures = []
    for project in projects:
        try:
            report = convert(project, args.scores/project.name/'slice_scores.csv')
            print(project.name, json.dumps(report['counts']))
        except (ValueError, OSError) as error:
            failures.append(str(error)); print(f'NOT READY: {project.name}: {error}')
    if failures:
        raise SystemExit(1)

if __name__ == '__main__':
    main()

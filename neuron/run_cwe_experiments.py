"""Run both experiments for every observed CWE and the combined dataset."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


def discover_cwes(paths):
    counts = {}
    for path in paths:
        with Path(path).open() as stream:
            for line in stream:
                if not line.strip():
                    continue
                row = json.loads(line)
                meta = {**row, **(row.get('metadata') or {})}
                labels = meta.get('cwe_ids') or []
                if isinstance(labels, str):
                    labels = [labels]
                labels = set(labels + [meta.get('CWE ID'), meta.get('cwe_id')])
                for label in labels:
                    if isinstance(label, str) and re.fullmatch(r'CWE-\d+', label):
                        counts[label] = counts.get(label, 0) + 1
    return counts


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--dataset', nargs='+', required=True)
    cli.add_argument('--output-dir', type=Path, required=True)
    cli.add_argument('--cwe-source', nargs='+', help='Discover CWEs from original sources, including those with no keep pairs')
    args = cli.parse_args()
    counts = discover_cwes(args.dataset)
    discovered = discover_cwes(args.cwe_source or args.dataset)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = args.output_dir / 'experiments.json'
    if summary_path.exists():
        cli.error('Experiment manifest exists; choose a new --output-dir')
    summary = {'dataset': args.dataset, 'available_pairs_by_cwe': counts, 'experiments': []}
    script_dir = Path(__file__).resolve().parent
    scopes = [None] + sorted(discovered, key=lambda c: int(c.split('-')[1]))
    for cwe in scopes:
        for model in ('modernbert', 'securebert2'):
            for script in ('neuron.py', 'function_probe.py'):
                scope = cwe or 'ALL'
                output = args.output_dir / scope
                command = [sys.executable, str(script_dir / script), '--model', model,
                           '--dataset', *args.dataset, '--output-dir', str(output)]
                if cwe:
                    command += ['--cwe', cwe]
                entry = dict(scope=scope, model=model, script=script, command=command)
                if cwe and not counts.get(cwe):
                    entry.update(status='skipped', reason='No retained pairs for this CWE')
                else:
                    output.mkdir(parents=True, exist_ok=True)
                    log_path = output / f'{Path(script).stem}_{model}.log'
                    print(f'Running {scope} / {model} / {script}', flush=True)
                    with log_path.open('w') as log:
                        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
                    entry.update(status='complete' if result.returncode == 0 else 'failed',
                                 returncode=result.returncode, log=str(log_path))
                    print(f"  {entry['status']}: {log_path}", flush=True)
                summary['experiments'].append(entry)
                summary_path.write_text(json.dumps(summary, indent=2))
    print(f'Saved experiment status: {summary_path}', flush=True)
    if any(e['status'] == 'failed' for e in summary['experiments']):
        sys.exit(1)


if __name__ == '__main__':
    main()

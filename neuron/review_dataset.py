"""Review dataset/source/*.jsonl once; reuse dataset/review/dataset.jsonl if present."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import traceback
from tqdm import tqdm

from core.model_config import MODEL_ID, MAX_LENGTH
from core.review_rules import MODEL, VERSION, PROMPT, digest, inspect_pair, make_parser
from core.review_backend import VLLMReviewer, backend_log, write_analysis


def file_hash(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def load_pairs(sources):
    pairs = []
    for source in sources:
        with source.open(encoding='utf-8') as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict) or any(not isinstance(row.get(k), str)
                        for k in ('func_before', 'func_after')):
                    raise ValueError(f'{source}:{line_number}: requires func_before/func_after strings')
                metadata = {k: v for k, v in row.items() if k not in ('func_before', 'func_after')}
                metadata.update(metadata.pop('metadata', {}) or {})
                metadata['review_source'] = {'path': str(source), 'line_number': line_number}
                pairs.append(dict(before=row['func_before'], after=row['func_after'], metadata=metadata))
    return pairs


def review_pairs(pairs, args, directory, config, run_id):
    runtime = directory / 'audit.jsonl.runtime.log'
    counts, seen, pending = Counter(), {}, []
    reviewer = None
    parser = make_parser()
    config['syntax_parsers'] = sorted(parser) if isinstance(parser, dict) else []
    with backend_log(runtime):
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    with (directory / 'audit.jsonl').open('w', encoding='utf-8') as audit, \
         (directory / 'dataset.jsonl').open('w', encoding='utf-8') as kept, \
         (directory / 'audit.jsonl.analysis.log').open('w', encoding='utf-8') as analysis, \
         tqdm(total=len(pairs), desc='Reviewing pairs', unit='pair') as progress:
        analysis.write(f'PAIR AUDIT {run_id}\nSystem prompt:\n{PROMPT}\n')

        def save(index, pair, checks, verdict):
            row = dict(verdict, run_id=run_id, pair_index=index, pair_hash=digest(pair),
                       deterministic_checks=checks, input=pair,
                       timestamp=datetime.now(timezone.utc).isoformat(),
                       model_revision=reviewer.resolved_revision if reviewer else None)
            audit.write(json.dumps(row, ensure_ascii=False) + '\n')
            audit.flush()
            write_analysis(analysis, row)
            if row['decision'] == 'keep':
                kept.write(json.dumps(dict(pair_id=row['pair_hash'], func_before=pair['before'],
                    func_after=pair['after'], metadata=pair['metadata'],
                    audit=dict(run_id=run_id, pair_index=index, decision='keep')), ensure_ascii=False) + '\n')
            counts[row['decision']] += 1
            progress.update(1)
            progress.set_postfix({k: counts[k] for k in ('keep', 'reject', 'review', 'excluded')}, refresh=False)

        def flush_batch():
            nonlocal reviewer
            if not pending:
                return
            with backend_log(runtime):
                if reviewer is None:
                    reviewer = VLLMReviewer(args)
                verdicts = reviewer.review_batch([(pair, checks) for _, pair, checks in pending])
            if len(verdicts) != len(pending):
                raise RuntimeError('Reviewer returned an unexpected number of results')
            for (index, pair, checks), verdict in zip(pending, verdicts):
                save(index, pair, checks, verdict)
            pending.clear()

        for index, pair in enumerate(pairs):
            code_hash = digest([pair['before'].strip(), pair['after'].strip()])
            duplicate = seen.get(code_hash)
            seen.setdefault(code_hash, index)
            checks = inspect_pair(pair, tokenizer, parser, args.encoder_limit)
            if duplicate is not None:
                checks['reject_reasons'].append('duplicate_pair')
                checks['duplicate_of'] = duplicate
            if checks['reject_reasons']:
                save(index, pair, checks, dict(decision='reject', reason_codes=checks['reject_reasons']))
            elif not checks['experiment_eligibility']['eligible']:
                save(index, pair, checks, dict(decision='excluded', quality_status='not_assessed',
                     reason_codes=checks['experiment_eligibility']['reasons']))
            else:
                pending.append((index, pair, checks))
                if len(pending) >= args.batch_size:
                    flush_batch()
        flush_batch()
    return dict(total_pairs=len(pairs), audited=sum(counts.values()), decisions=dict(counts),
                model_revision=reviewer.resolved_revision if reviewer else None)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--force-review', action='store_true', help='Regenerate even if dataset.jsonl exists')
    cli.add_argument('--model', default=MODEL)
    cli.add_argument('--revision', default='main')
    cli.add_argument('--batch-size', type=int, default=8)
    cli.add_argument('--tensor-parallel-size', type=int, default=1)
    cli.add_argument('--gpu-memory-utilization', type=float, default=0.85)
    cli.add_argument('--seed', type=int, default=42)
    cli.add_argument('--max-input-tokens', type=int, default=8192)
    cli.add_argument('--max-new-tokens', type=int, default=1536)
    cli.add_argument('--encoder-limit', type=int, default=MAX_LENGTH)
    args = cli.parse_args()
    root = Path(__file__).resolve().parent
    output = root / 'dataset/review'
    if (output / 'dataset.jsonl').is_file() and not args.force_review:
        print(f'Reusing existing reviewed dataset: {output / "dataset.jsonl"}', flush=True)
        return
    if min(args.batch_size, args.tensor_parallel_size, args.max_input_tokens,
           args.max_new_tokens, args.encoder_limit) <= 0:
        cli.error('Batch size, parallel size and token limits must be positive')
    if not 0 < args.gpu_memory_utilization < 1 or args.encoder_limit > MAX_LENGTH:
        cli.error(f'GPU utilization must be between 0 and 1; encoder limit must be <= {MAX_LENGTH}')
    sources = sorted((root / 'dataset/source').glob('*.jsonl'))
    if not sources:
        cli.error('No source JSONL files found in dataset/source')
    pairs = load_pairs(sources)
    output.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='.pending_', dir=output))
    started = datetime.now(timezone.utc).isoformat()
    config = dict(vars(args), encoder_model=MODEL_ID, prompt_version=VERSION, prompt_hash=digest(PROMPT))
    run_id = digest(dict(started_at=started, config=config))
    print(f'Reviewing {len(pairs)} pairs from {len(sources)} source files\nWorking directory: {directory}', flush=True)
    try:
        summary = review_pairs(pairs, args, directory, config, run_id)
        summary.update(run_id=run_id, config=config, started_at=started,
                       finished_at=datetime.now(timezone.utc).isoformat(),
                       sources=[dict(path=str(p), sha256=file_hash(p)) for p in sources])
        (directory / 'report.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
        # Publish the dataset last: its existence is the only completion marker.
        for name in ('audit.jsonl', 'audit.jsonl.analysis.log', 'audit.jsonl.runtime.log', 'report.json', 'dataset.jsonl'):
            (directory / name).replace(output / name)
        directory.rmdir()
    except BaseException:
        with (directory / 'audit.jsonl.runtime.log').open('a') as log:
            traceback.print_exc(file=log)
        print(f'Review failed; diagnostics retained in {directory}', file=sys.stderr)
        raise
    print(f'Reviewed dataset: {output / "dataset.jsonl"}', flush=True)
    print(json.dumps({k: summary[k] for k in ('total_pairs', 'audited', 'decisions')}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as error:
        print(f'Audit failed: {error}', file=sys.stderr)
        sys.exit(1)

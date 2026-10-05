"""Reuse completed audits only when their content/configuration identity matches."""
import hashlib
import json
from pathlib import Path


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def find_completed(root, run_id, total_pairs):
    for path in sorted(Path(root).rglob('review_dataset_*/report.json'), reverse=True):
        try:
            report = json.loads(path.read_text())
            if (report.get('run_id') != run_id or report.get('total_pairs') != total_pairs
                    or report.get('audited') != total_pairs):
                continue
            hashes = report.get('artifact_hashes', {})
            if not all(hashes.get(name) and file_hash(path.parent / name) == hashes[name]
                       for name in ('kept.jsonl', 'audit.jsonl')):
                continue
            if not all((path.parent / name).is_file() for name in
                       ('run.json', 'audit.jsonl.analysis.log', 'audit.jsonl.runtime.log')):
                continue
            return path.parent.resolve(), report
        except (OSError, ValueError, TypeError):
            continue
    return None


def reuse_completed(directory, report, target, metadata):
    # Resolve links so deleting an intermediate reused run does not break the chain.
    for name in ('kept.jsonl', 'audit.jsonl', 'audit.jsonl.analysis.log', 'audit.jsonl.runtime.log'):
        (target / name).symlink_to((directory / name).resolve())
    metadata['review_reused_from'] = str(directory)
    metadata['review_model_revisions'] = report.get('model_revisions', [])
    (target / 'run.json').write_text(json.dumps(metadata, indent=2))
    summary = dict(report, run=metadata, reused_from=str(directory))
    (target / 'report.json').write_text(json.dumps(summary, indent=2))

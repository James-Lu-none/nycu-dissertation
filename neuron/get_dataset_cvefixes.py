"""Export conservative, traceable C function pairs from the CVEfixes SQLite database.

No source execution, network access, or database mutation. Ambiguous matches are
recorded for review rather than resolved by source order or Cartesian joins.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sqlite3

VERSION = 'cvefixes-pairs-v2'


def stable_id(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def pair_methods(methods):
    sides = {'before': [], 'after': []}
    issues = []
    for m in methods:
        marker = str(m['before_change']).lower()
        side = 'before' if marker in ('true', '1') else 'after' if marker in ('false', '0') else None
        if side is None:
            issues.append({'reason': 'unknown_before_change', 'method_ids': [m['method_change_id']]})
        else:
            sides[side].append(m)
    pairs = []
    used = set()
    # Do not guess signature changes or renamed functions. These remain in review.
    groups = defaultdict(lambda: {'before': [], 'after': []})
    for side, entries in sides.items():
        for m in entries:
            signature = (m['signature'] or '').strip()
            if signature:
                groups[signature][side].append(m)
    for signature, group in sorted(groups.items()):
        b, a = group['before'], group['after']
        if len(b) == len(a) == 1:
            pairs.append((b[0], a[0]))
            used.update([b[0]['method_change_id'], a[0]['method_change_id']])
        elif b and a:
            ids = [m['method_change_id'] for m in b + a]
            issues.append({'reason': 'ambiguous_signature', 'signature': signature, 'method_ids': ids})
            used.update(ids)
    remaining = [dict(side=side, method_id=m['method_change_id'], name=m['name'],
                      signature=m['signature']) for side, entries in sides.items()
                 for m in entries if m['method_change_id'] not in used]
    if remaining:
        issues.append({'reason': 'unmatched_methods', 'methods': remaining})
    return pairs, issues


def write_json(stream, obj):
    stream.write(json.dumps(obj, ensure_ascii=False) + '\n')


def export(db, output, cwes=()):
    # New directory avoids silently overwriting earlier experiments or partial runs.
    if not db.is_file():
        raise FileNotFoundError(db)
    output.mkdir(parents=True, exist_ok=False)
    counts = Counter()
    conn = sqlite3.connect(db.resolve().as_uri() + '?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row
    try:
        # Aggregate CVEs/CWEs before touching large source-code tables.
        cve_info = {r['cve_id']: dict(r) for r in conn.execute('SELECT cve_id, description FROM cve')}
        classifications = defaultdict(set)
        for r in conn.execute('SELECT cve_id, cwe_id FROM cwe_classification'):
            if r['cwe_id']:
                classifications[r['cve_id']].add(r['cwe_id'])
        fixes = defaultdict(set)
        for r in conn.execute('SELECT cve_id, hash, repo_url FROM fixes'):
            fixes[(r['hash'], r['repo_url'])].add(r['cve_id'])
        commits = defaultdict(list)
        for r in conn.execute('SELECT hash, repo_url, msg, parents FROM commits'):
            ids = sorted(fixes.get((r['hash'], r['repo_url']), ()))
            if ids:
                commits[r['hash']].append(dict(r, cve_ids=ids))
        print('Reading C file metadata...', flush=True)
        files = [dict(r) for r in conn.execute(
            "SELECT file_change_id, hash, old_path, new_path, change_type, programming_language "
            "FROM file_change WHERE programming_language='C' ORDER BY hash, file_change_id")]
        selected_files = set()
        for file in files:
            sources = commits.get(file['hash'], [])
            if len(sources) == 1:
                labels = set().union(*(classifications[i] for i in sources[0]['cve_ids']))
                if not cwes or set(cwes).intersection(labels):
                    selected_files.add(file['file_change_id'])
        print(f'Reading methods for {len(selected_files)} selected files...', flush=True)
        # Avoid a large automatic join index and keep only selected method bodies.
        methods = defaultdict(list)
        conn.execute('CREATE TEMP TABLE selected_files (id TEXT PRIMARY KEY)')
        conn.executemany('INSERT INTO selected_files VALUES (?)', [(i,) for i in selected_files])
        for row in conn.execute('SELECT m.* FROM method_change m WHERE EXISTS '
                                '(SELECT 1 FROM selected_files s WHERE s.id=m.file_change_id)'):
            methods[row['file_change_id']].append(dict(row))
        seen_sources = set()
        seen_code = {}
        names = ['vulnerable.jsonl', 'patched.jsonl', 'pairs.jsonl', 'review.jsonl']
        from contextlib import ExitStack
        with ExitStack() as stack:
            vout, pout, pairsout, review = [stack.enter_context((output / name).open('w')) for name in names]
            for file in files:
                counts['c_files'] += 1
                sources = commits.get(file['hash'], [])
                if len(sources) != 1:
                    counts['missing_or_ambiguous_commit_files'] += 1
                    write_json(review, dict(file=file, reason='missing_or_ambiguous_commit'))
                    continue
                commit = sources[0]
                ids = commit['cve_ids']
                all_cwes = sorted(set().union(*(classifications[i] for i in ids)))
                if cwes and not set(cwes).intersection(all_cwes):
                    counts['excluded_cwe_files'] += 1
                    continue
                pairs, issues = pair_methods(methods.pop(file['file_change_id'], []))
                for issue in issues:
                    counts[issue['reason']] += 1
                    write_json(review, dict(issue, file=file, cve_ids=ids))
                for before, after in pairs:
                    counts['matched_candidates'] += 1
                    codes = [before['code'], after['code']]
                    if any(not isinstance(c, str) or not c.strip() for c in codes):
                        counts['empty_code_pairs'] += 1
                        continue
                    if codes[0].strip() == codes[1].strip():
                        counts['identical_code_pairs'] += 1
                        continue
                    source = [commit['repo_url'], file['hash'], file['file_change_id'],
                              before['method_change_id'], after['method_change_id']]
                    pid = stable_id(source)
                    if pid in seen_sources:
                        counts['duplicate_source_pairs'] += 1
                        continue
                    seen_sources.add(pid)
                    code_hash = stable_id([c.strip() for c in codes])
                    duplicate = seen_code.get(code_hash)
                    seen_code.setdefault(code_hash, pid)
                    counts['repeated_code_pairs'] += duplicate is not None
                    # Keep all source associations. Exact-code duplicates can be grouped downstream.
                    meta = dict(file, repo_url=commit['repo_url'], commit_id=file['hash'],
                                commit_message=commit['msg'], parents=commit['parents'],
                                cve_ids=ids, cwe_ids=all_cwes, lang='C',
                                cve_description='\n\n'.join(f"{i}: {cve_info.get(i, {}).get('description') or ''}"
                                                         for i in ids if cve_info.get(i, {}).get('description')),
                                cve_records=[dict(cve_info.get(i, {'cve_id': i}),
                                                  cwe_ids=sorted(classifications[i])) for i in ids],
                                methods={side: {k: m[k] for k in ('method_change_id', 'name', 'signature',
                                                                 'start_line', 'end_line')}
                                         for side, m in [('before', before), ('after', after)]},
                                pairing_policy='unique_exact_signature_within_file',
                                label_policy='pre/post fixing commit; not verified vulnerability labels',
                                code_pair_hash=code_hash, duplicate_code_of=duplicate)
                    for stream, code, side in [(vout, codes[0], 'before'), (pout, codes[1], 'after')]:
                        write_json(stream, dict(id=pid, pair_id=pid, cve_ids=ids, code=code,
                                                metadata=dict(meta, side=side)))
                    
                    # Make unified jsonl match BigVul format
                    unified_record = {
                        "pair_id": pid,
                        "func_before": codes[0],
                        "func_after": codes[1],
                        "metadata": meta
                    }
                    write_json(pairsout, unified_record)
                    counts['exported_pairs'] += 1
                if counts['c_files'] % 1000 == 0:
                    print(dict(counts), flush=True)
        report = dict(version=VERSION, database=str(db.resolve()), database_size=db.stat().st_size,
                      cwe_filter=list(cwes), counts=dict(counts),
                      notes=['No tokenizer or syntax validation applied; run audit before training.',
                             'Renames/signature changes and ambiguous matches require separate review.',
                             'Repeated code retains provenance; group/deduplicate before training.'])
        (output / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return report
    finally:
        conn.close()


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--db', type=Path, default=Path(__file__).resolve().parent / 'Data/CVEfixes.db')
    cli.add_argument('--output-dir', type=Path, default=Path(__file__).resolve().parent / 'neuron_pairs_v2')
    cli.add_argument('--cwe', action='append', default=[], help='Exact CWE ID; repeat for union. Default: all CWEs')
    args = cli.parse_args()
    export(args.db, args.output_dir, args.cwe)


if __name__ == '__main__':
    main()

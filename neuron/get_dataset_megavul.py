"""Stream MegaVul into deduplicated, normalized before/after pair JSONL."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

SOURCE_DIR = Path(__file__).resolve().parent / 'dataset/source'
VERSION = 'megavul-pairs-v2'


def stable_id(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def pair_hash(before, after):
    return stable_id([before.strip(), after.strip()])


def as_list(value):
    return [value] if isinstance(value, str) and value else list(value or [])


def convert_row(row, index):
    if row.get('is_vul') not in (True, 1):
        return None, 'non_vulnerable'
    before, after = row.get('func_before'), row.get('func')
    if any(not isinstance(code, str) or not code.strip() for code in (before, after)):
        return None, 'missing_or_invalid_code'
    if before.strip() == after.strip():
        return None, 'identical_code'
    excluded = {'func_before', 'func', 'parameter_list_before', 'parameter_list',
                'abstract_func_before', 'abstract_symbol_table_before', 'func_graph_path_before',
                'abstract_func', 'abstract_symbol_table', 'func_graph_path'}
    meta = {k: v for k, v in row.items() if k not in excluded}
    meta.update(cve_ids=sorted(set(as_list(row.get('cve_id')))),
                cwe_ids=sorted(set(as_list(row.get('cwe_ids')))),
                commit_id=row.get('commit_hash'), commit_message=row.get('commit_msg'),
                source_dataset='MegaVul')
    # Keep original fields, signatures, diff and source location for auditability.
    identity = [row.get(k) for k in ('repo_name', 'cve_id', 'commit_hash', 'file_path',
                                    'func_name', 'parameter_list_signature_before', 'parameter_list_signature')]
    identity.append(pair_hash(before, after))
    meta['source_records'] = [dict(row_index=index, repo_name=row.get('repo_name'),
                                   cve_id=row.get('cve_id'), commit_hash=row.get('commit_hash'),
                                   file_path=row.get('file_path'), func_name=row.get('func_name'))]
    return dict(pair_id=stable_id(['MegaVul', *identity]), func_before=before,
                func_after=after, metadata=meta), None


def export_rows(rows, output, exclude_existing=()):
    output = Path(output)
    report_path = output.with_suffix('.report.json')
    if output.exists() or report_path.exists():
        raise FileExistsError('Output/report exists; choose another --output')
    excluded_pairs, references = set(), []
    for source in map(Path, exclude_existing):
        if source.resolve() in (output.resolve(), report_path.resolve()):
            raise ValueError('Reference must not be an output')
        with source.open() as stream:
            for line in stream:
                if line.strip():
                    r = json.loads(line)
                    excluded_pairs.add(pair_hash(r['func_before'], r['func_after']))
        references.append(dict(path=str(source.resolve()), sha256=file_hash(source)))
    counts, retained = Counter(), {}
    for index, row in enumerate(rows):
        counts['processed'] += 1
        pair, reason = convert_row(row, index)
        if reason:
            counts[reason] += 1
            continue
        key = pair_hash(pair['func_before'], pair['func_after'])
        if key in excluded_pairs:
            counts['duplicate_existing_dataset'] += 1
            continue
        if key in retained:
            counts['duplicate_within_megavul'] += 1
            prior = retained[key]['metadata']
            for field in ('cve_ids', 'cwe_ids'):
                prior[field] = sorted(set(prior[field]) | set(pair['metadata'][field]))
            prior['source_records'].extend(pair['metadata']['source_records'])
        else:
            retained[key] = pair
    counts['exported'] = len(retained)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as stream:
        for pair in retained.values():
            stream.write(json.dumps(pair, ensure_ascii=False) + '\n')
    report = dict(version=VERSION, counts=dict(counts), exclude_existing=references,
                  policy='Exact ordered before/after text after strip; first pair retained; internal CWE/CVE labels merged',
                  languages='C/C++ retained; no language inferred from headers')
    with report_path.open('x') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    return report


def extract_megavul(input_path, output_path, exclude_existing=()):
    import ijson
    from tqdm import tqdm
    input_path, output_path = Path(input_path), Path(output_path)
    if input_path.resolve() in (output_path.resolve(), output_path.with_suffix('.report.json').resolve()):
        raise ValueError('Input must not be an output')
    with input_path.open('rb') as stream:
        report = export_rows(tqdm(ijson.items(stream, 'item', use_float=True), desc='MegaVul'),
                             output_path, exclude_existing)
    report['source'] = dict(path=str(input_path.resolve()), sha256=file_hash(input_path))
    output_path.with_suffix('.report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return report


if __name__ == '__main__':
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--input', type=Path, default=SOURCE_DIR / 'megavul.json')
    cli.add_argument('--output', type=Path, default=SOURCE_DIR / 'megavul.jsonl')
    cli.add_argument('--exclude-existing', type=Path, nargs='*',
                     default=[p for p in (SOURCE_DIR/'bigvul.jsonl', SOURCE_DIR/'cvefixes.jsonl') if p.exists()],
                     help='Exclude pairs already in these files; defaults to existing BigVul/CVEfixes. Pass empty to disable.')
    args = cli.parse_args()
    extract_megavul(args.input, args.output, args.exclude_existing)

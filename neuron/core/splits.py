"""Deterministic pair-level splits with CVE and exact-code overlap protection."""
import hashlib
import json
import random


def load_paired_records(vulnerable_path, patched_path):
    def read(path):
        with open(path) as stream:
            return [json.loads(line) for line in stream]
    vulnerable, patched = read(vulnerable_path), read(patched_path)
    if len(vulnerable) != len(patched):
        raise ValueError('Vulnerable and patched datasets must have equal lengths')
    for i, (v, p) in enumerate(zip(vulnerable, patched)):
        if v.get('id') != p.get('id'):
            raise ValueError(f'Pair {i}: mismatched source IDs')
        if not isinstance(v.get('code'), str) or not isinstance(p.get('code'), str):
            raise ValueError(f'Pair {i}: code must be a string on both sides')
    return list(zip(vulnerable, patched))

def load_unified_records(unified_path, cwe_filter=None):
    pairs = []
    with open(unified_path) as stream:
        for line in stream:
            record = json.loads(line)
            meta = record.get('metadata', {})
            
            if cwe_filter:
                cwes = []
                if "CWE ID" in meta:
                    cwes.append(meta["CWE ID"])
                if "cwe_ids" in meta:
                    cwes.extend(meta["cwe_ids"])
                
                if not set(cwe_filter).intersection(set(cwes)):
                    continue
            
            v = {
                'id': record.get('pair_id'),
                'code': record.get('func_before', ''),
                'metadata': meta
            }
            p = {
                'id': record.get('pair_id'),
                'code': record.get('func_after', ''),
                'metadata': meta
            }
            pairs.append((v, p))
    return pairs


def split_pairs(records, eligible_indices, seed=42):
    """Approximate 70/15/15 group split; return original record indices.

    Shared nonempty IDs or identical function text (on either side) link pairs.
    This prevents exact overlap, not all near-duplicate or project overlap.
    """
    indices = sorted(set(eligible_indices))
    parent = {i: i for i in indices}

    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    seen = {}
    for i in indices:
        v, p = records[i]
        keys = []
        source_id = str(v.get('id') or '').strip()
        if source_id:
            keys.append(('id', source_id))
        for record in (v, p):
            metadata = record.get('metadata') or {}
            cves = record.get('cve_ids') or metadata.get('cve_ids') or []
            if isinstance(cves, str):
                cves = [cves]
            cves = list(cves) + [metadata.get('CVE ID'), metadata.get('cve_id')]
            keys.extend(('cve', cve) for cve in cves if cve)
            commit = metadata.get('commit_id') or metadata.get('hash')
            if commit:
                keys.append(('commit', commit))
            code = record['code'].strip()
            if code:
                keys.append(('code', hashlib.sha256(code.encode()).hexdigest()))
        for key in keys:
            if key in seen:
                parent[root(i)] = root(seen[key])
            else:
                seen[key] = i
    groups = {}
    for i in indices:
        groups.setdefault(root(i), []).append(i)
    groups = list(groups.values())
    if len(groups) < 3:
        raise ValueError('At least three independent groups are required for train/validation/test')
    random.Random(seed).shuffle(groups)
    n_validation = max(1, round(len(groups) * .15))
    n_test = max(1, round(len(groups) * .15))
    boundaries = (len(groups) - n_validation - n_test, len(groups) - n_test)
    parts = (groups[:boundaries[0]], groups[boundaries[0]:boundaries[1]], groups[boundaries[1]:])
    return {name: sorted(i for group in part for i in group)
            for name, part in zip(('train', 'validation', 'test'), parts)}

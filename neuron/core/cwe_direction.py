"""Known-CWE diagnostic: fixed B layer, train-only directions, no learned router."""
import re
from collections import Counter
import torch


def cwe_labels(pair):
    meta = pair[0].get('metadata') or {}
    values = meta.get('cwe_ids') or []
    if isinstance(values, str):
        values = [values]
    values = list(values) + [meta.get('CWE ID', '')]
    return sorted({label for value in values for label in re.findall(r'CWE-\d+', str(value))})


def fit_directions(deltas, pairs, min_pairs):
    if min_pairs < 1 or len(deltas) != len(pairs) or not len(pairs):
        raise ValueError('Require positive minimum and aligned, nonempty training pairs')
    if not torch.isfinite(deltas).all():
        raise ValueError('Nonfinite training deltas')
    counts = Counter(label for pair in pairs for label in cwe_labels(pair))
    directions = {}
    for label, count in sorted(counts.items()):
        if count >= min_pairs:
            indices = [i for i, pair in enumerate(pairs) if label in cwe_labels(pair)]
            direction = deltas[indices].mean(0)
            if direction.norm() > 0:
                directions[label] = direction / direction.norm()
    return directions, dict(counts)


def select_direction(pair, directions, counts):
    # Metadata only; never select by changed-line labels or test performance.
    eligible = [c for c in cwe_labels(pair) if c in directions]
    return min(eligible, key=lambda c: (-counts[c], c)) if eligible else 'ALL'

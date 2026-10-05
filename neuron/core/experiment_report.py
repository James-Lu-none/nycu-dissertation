"""Compact aggregate CSV; pair-level values remain in memory only."""
import csv
import numpy as np
from function_probe import connected_groups


def uncertainty(per_pair, key, records, repeats, seed):
    result = dict(test_groups=0, mrr_ci_low=None, mrr_ci_high=None,
                  mrr_minus_random_ci_low=None, mrr_minus_random_ci_high=None,
                  p_vs_random=None)
    if not per_pair:
        return result
    safe_records = [tuple(dict(r, metadata=r.get('metadata') or {}) for r in pair) for pair in records]
    groups = connected_groups(safe_records, [p['index'] for p in per_pair])
    result['test_groups'] = len(groups)
    if len(groups) < 2 or not repeats:
        return result
    values = np.array([p['layers'][key]['mrr'] for p in per_pair])
    delta = values - np.array([p['random']['mrr'] for p in per_pair])
    sizes = np.array([len(g) for g in groups])
    sums = np.array([[values[g].sum(), delta[g].sum()] for g in groups])
    rng = np.random.default_rng(seed)
    draws = []
    exceed = 0
    observed = abs(delta.mean())
    for _ in range(repeats):
        sample = rng.integers(len(groups), size=len(groups))
        draws.append(sums[sample].sum(0) / sizes[sample].sum())
        permuted = (sums[:, 1] * rng.choice([-1, 1], len(groups))).sum() / len(values)
        exceed += abs(permuted) >= observed
    intervals = np.quantile(draws, [.025, .975], axis=0)
    result.update(mrr_ci_low=intervals[0, 0], mrr_ci_high=intervals[1, 0],
                  mrr_minus_random_ci_low=intervals[0, 1], mrr_minus_random_ci_high=intervals[1, 1],
                  p_vs_random=(exceed + 1)/(repeats + 1))
    return result


def write_csv(path, rows):
    # Holm correction across all reported test comparisons in this run.
    ordered = sorted((r['p_vs_random'], i) for i, r in enumerate(rows) if r.get('p_vs_random') is not None)
    maximum = 0.
    for rank, (p, i) in enumerate(ordered):
        maximum = max(maximum, min(1., p * (len(ordered) - rank)))
        rows[i]['p_vs_random_holm'] = maximum
    fields = list(dict.fromkeys(k for r in rows for k in r))
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

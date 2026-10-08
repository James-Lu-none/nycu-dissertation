"""Region-level SVM diagnostics; separate from line localization and selection."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import json
import numpy as np
from sklearn.metrics import roc_auc_score, balanced_accuracy_score
from threadpoolctl import threadpool_limits
from tqdm import tqdm
from .fit_jobs import worker_count


def score_regions(info, representations, batch_size=512):
    results = {}
    for split, (v, p) in representations.items():
        x = np.concatenate([v, p])
        y = np.r_[np.ones(len(v)), np.zeros(len(p))]
        if not len(v) or not len(p):
            results[split] = dict(auroc=None, balanced_accuracy=None, pairs=0, scores=np.empty(0))
            continue
        margins = np.concatenate([info['estimator'].decision_function(x[i:i + batch_size])
                                  for i in range(0, len(x), batch_size)])
        if not np.isfinite(margins).all():
            raise ValueError('Nonfinite RBF region margins')
        results[split] = dict(auroc=float(roc_auc_score(y, margins)),
            balanced_accuracy=float(balanced_accuracy_score(y, margins > 0)),
            pairs=len(v), scores=np.tanh(margins))
    return results


def report_regions(candidates, train, validation, output, jobs=24):
    import matplotlib.pyplot as plt
    output.mkdir(parents=True, exist_ok=True)
    reps = {}
    for info in candidates.values():
        layer = info['layer']
        if layer in reps:
            continue
        weights = info['down_proj']
        reps[layer] = {split: tuple((summaries[side]['line_mean'][layer] @ weights).numpy()
                                    for side in ('vulnerable', 'patched'))
                       for split, summaries in (('train', train), ('validation', validation))}
    results = {}
    with threadpool_limits(limits=1), ThreadPoolExecutor(max_workers=worker_count(jobs)) as pool:
        tasks = {pool.submit(score_regions, info, reps[info['layer']]): key for key, info in candidates.items()}
        for future in tqdm(as_completed(tasks), total=len(tasks), desc='E region diagnostics', unit='model'):
            results[tasks[future]] = future.result()
    rows = []
    bins = np.linspace(-1, 1, 41)
    for layer in sorted(reps):
        keys = [key for key, info in candidates.items() if info['layer'] == layer]
        fig, axes = plt.subplots(len(keys), 2, figsize=(10, 3 * len(keys)), squeeze=False)
        for row_index, key in enumerate(keys):
            info, metrics = candidates[key], results[key]
            n_sv = len(info['estimator'][-1].support_)
            train_samples = 2 * metrics['train']['pairs']
            row = dict(method='E', layer=layer, parameter=json.dumps(info['parameter'], sort_keys=True),
                       support_vectors=n_sv, train_samples=train_samples,
                       support_vector_ratio=n_sv / train_samples if train_samples else None)
            for column, split in enumerate(('train', 'validation')):
                data = metrics[split]
                for name in ('auroc', 'balanced_accuracy', 'pairs'):
                    row[f'{split}_{name}'] = data[name]
                ax = axes[row_index, column]
                n = data['pairs']
                if n:
                    ax.hist(data['scores'][:n], bins=bins, density=True, alpha=.5, label='Vulnerable', color='red')
                    ax.hist(data['scores'][n:], bins=bins, density=True, alpha=.5, label='Patched', color='blue')
                else:
                    ax.text(.1, .5, 'No valid region pairs', transform=ax.transAxes)
                ax.set(xlim=(-1, 1), xlabel='tanh(decision_function); not probability', ylabel='Density',
                       title=f"Layer {layer} | {split} | {info['parameter']}")
                ax.axvline(0, color='black', linestyle='--', linewidth=.7)
                if n:
                    ax.legend()
            rows.append(row)
        fig.tight_layout()
        fig.savefig(output / f'layer_{layer}.png', dpi=150)
        plt.close(fig)
    with (output.parent / 'rbf_region_report.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]) if rows else [])
        writer.writeheader()
        writer.writerows(rows)
    return rows

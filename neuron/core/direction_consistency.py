"""Train-pair direction diagnostics, not evidence of causal security semantics."""
import torch


def direction_consistency(vulnerable, patched):
    delta = (vulnerable - patched).detach().cpu().double()
    if delta.ndim != 2 or not len(delta) or not torch.isfinite(delta).all():
        raise ValueError('Expected nonempty finite paired representations')
    total = delta.sum(0)
    mean = total / len(delta)
    norms = delta.norm(dim=1)

    def summarize(reference):
        ref_norms = reference.norm(dim=1)
        valid = (norms > 0) & (ref_norms > 0)
        values = torch.full_like(norms, float('nan'))
        values[valid] = ((delta[valid] * reference[valid]).sum(1) /
                         (norms[valid] * ref_norms[valid])).clamp(-1, 1)
        usable = values[valid]
        return dict(valid_pairs=int(valid.sum()), undefined_pairs=int((~valid).sum()),
                    positive_fraction=float((usable > 0).double().mean()) if len(usable) else None,
                    mean=float(usable.mean()) if len(usable) else None,
                    std=float(usable.std(unbiased=False)) if len(usable) else None,
                    quantiles={str(q): float(torch.quantile(usable, q)) if len(usable) else None
                               for q in (0., .1, .25, .5, .75, .9, 1.)},
                    cosines=[float(v) if ok else None for v, ok in zip(values, valid)])

    loo = (total[None, :] - delta) / max(len(delta) - 1, 1)
    return dict(pair_count=len(delta), zero_delta_pairs=int((norms == 0).sum()),
                mean_direction_norm=float(mean.norm()), mean_delta_norm=float(norms.mean()),
                coherence_ratio=float(mean.norm() / norms.mean()) if norms.mean() > 0 else None,
                delta_norms=norms.tolist(),
                cosine_to_mean=summarize(mean.expand_as(delta)),
                cosine_to_leave_one_out_mean=summarize(loo))


def plot_consistency(reports, output_path):
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(12, 4), sharey=True)
    for ax, key, title in zip(axes, ['cosine_to_mean', 'cosine_to_leave_one_out_mean'],
                             ['Pair vs mean direction', 'Pair vs leave-one-out mean']):
        for method, layers in reports.items():
            ids = sorted(layers)
            means = [layers[l][key]['mean'] if layers[l][key]['mean'] is not None else float('nan') for l in ids]
            low = [layers[l][key]['quantiles']['0.25'] if layers[l][key]['mean'] is not None else float('nan') for l in ids]
            high = [layers[l][key]['quantiles']['0.75'] if layers[l][key]['mean'] is not None else float('nan') for l in ids]
            ax.plot(ids, means, label=method)
            ax.fill_between(ids, low, high, alpha=.15)
        ax.axhline(0, color='gray', linestyle='--')
        ax.set(title=title, xlabel='Layer', ylabel='Cosine (mean; shaded IQR)', ylim=(-1, 1))
        ax.legend()
    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)

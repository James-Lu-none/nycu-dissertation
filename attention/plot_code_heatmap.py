"""Align code and A/B/C scores colored by within-method rank percentile."""
import argparse
import csv
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.colors import Normalize
from matplotlib.patches import Rectangle
from matplotlib.cm import ScalarMappable
import numpy as np

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT/'outputs/synthetic_bounds/line_scores.csv')
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    groups = {}
    with args.input.open() as stream:
        for row in csv.DictReader(stream):
            key = row.get('sample') or 'pair_'+row['pair']
            groups.setdefault(key, []).append(row)
    output = args.output_dir or args.input.parent/'heatmaps'
    output.mkdir(parents=True, exist_ok=True)
    all_scores = [float(r[m]) for rows in groups.values() for r in rows
                  for m in ('A', 'B', 'C') if r[m] not in ('', 'NA')]
    if not all_scores or not np.isfinite(all_scores).all() or min(all_scores) < 0:
        raise ValueError('Expected finite nonnegative scores')
    norm = Normalize(0, 1)
    cmap = plt.get_cmap('coolwarm').copy()
    cmap.set_bad('#eeeeee')
    for name, rows in groups.items():
        rows.sort(key=lambda r: int(r['line']))
        values = np.array([[float(r[m]) if r[m] not in ('', 'NA') else np.nan
                            for m in ('A', 'B', 'C')] for r in rows])
        ranks = np.zeros_like(values, dtype=int)
        percentiles = np.full_like(values, np.nan)
        for j in range(3):
            valid = np.isfinite(values[:, j])
            if not valid.any():
                continue
            for i in np.flatnonzero(valid):
                ranks[i, j] = 1 + np.count_nonzero(values[valid, j] > values[i, j])
                column = values[valid, j]
                lower = np.count_nonzero(column < values[i, j])
                equal = np.count_nonzero(column == values[i, j])
                # Average-rank percentile: tied/all-equal scores get equal colors.
                percentiles[i, j] = (lower + (equal-1)/2)/(len(column)-1) if len(column)>1 else .5
        code = [r['code'].expandtabs(4) for r in rows]
        width = max(10, max(map(len, code), default=0)*.082)
        fig = plt.figure(figsize=(6.4+width, max(4, .32*len(rows)+2)))
        grid = fig.add_gridspec(1, 2, width_ratios=[5.4, width], wspace=.025,
                               left=.025, right=.985, bottom=.12, top=.87)
        heat = fig.add_subplot(grid[0, 0])
        source = fig.add_subplot(grid[0, 1], sharey=heat)
        heat.imshow(np.ma.masked_invalid(percentiles), cmap=cmap, norm=norm, aspect='auto')
        for i in range(len(rows)):
            for j in range(3):
                val = values[i, j]
                text = f'{val:.4f} (#{ranks[i,j]})' if np.isfinite(val) else 'NA'
                percentile = percentiles[i, j]
                color = 'white' if np.isfinite(percentile) and (percentile < .12 or percentile > .88) else '#111111'
                top = 0 < ranks[i, j] <= 3
                heat.text(j, i, text, ha='center', va='center', fontsize=9, color=color,
                          fontfamily='monospace', fontweight='bold' if top else 'normal')
                if top:
                    heat.add_patch(Rectangle((j-.48, i-.46), .96, .92, fill=False,
                                             edgecolor='#222222', linewidth=1.3, zorder=4))
        heat.set_xticks([0, 1, 2], ['A', 'B', 'C'])
        heat.tick_params(top=True, labeltop=True, bottom=False, labelbottom=False, left=False, labelleft=False)
        heat.set_xticks(np.arange(-.5, 3, 1), minor=True)
        heat.set_yticks(np.arange(-.5, len(rows), 1), minor=True)
        heat.grid(which='minor', color='white', linewidth=1)
        heat.tick_params(which='minor', length=0)
        source.set_xlim(0, 1)
        source.set_ylim(len(rows)-.5, -.5)
        source.axis('off')
        for i, (row, line) in enumerate(zip(rows, code)):
            if i % 2 == 0:
                source.axhspan(i-.5, i+.5, color='#f5f5f5', zorder=0)
            source.text(.008, i, f'{int(row["line"]):3d}  {line}', va='center',
                        fontsize=10, fontfamily='monospace')
        source.set_title('Source code', loc='left', fontsize=11)
        fig.suptitle(name, fontsize=15, y=.97)
        fig.text(.025, .92, 'A: attention distance    B: cls-classification    C: cls-classification_with_rational', fontsize=10)
        bar_ax = fig.add_axes([.025, .05, .20, .017])
        bar = fig.colorbar(ScalarMappable(norm=norm, cmap=cmap), cax=bar_ax, orientation='horizontal')
        bar.set_ticks([0, .5, 1], labels=['0% (lowest)', '50%', '100% (highest)'])
        bar.ax.get_xticklabels()[0].set_ha('left')
        bar.ax.get_xticklabels()[-1].set_ha('right')
        bar.ax.set_title('Within-method rank percentile', fontsize=9)
        fig.text(.26, .05, 'Colors: relative rank within each sample/method, not score magnitude or vulnerability risk.\nNumbers: original score (#rank); boxes: top 3 ranks; NA: gray. Tied colors use average rank.', fontsize=9)
        for suffix in ('png', 'pdf'):
            fig.savefig(output/f'{name}.{suffix}', dpi=180)
        plt.close(fig)
    print(f'Saved {len(groups)} code heatmaps: {output}')


if __name__ == '__main__':
    main()

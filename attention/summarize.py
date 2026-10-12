"""Combine experiment CSVs and plot held-out localization/classification."""
import csv
from pathlib import Path
import sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def main():
    root=Path(sys.argv[1]); rows=[]
    for path in sorted(root.glob('*/report.csv')):
        with path.open() as f:
            rows.extend(dict(experiment=path.parent.name,**row) for row in csv.DictReader(f))
    if not rows: raise ValueError('No reports')
    with (root/'comparison.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    selected=[r for r in rows if r['split']=='test' and r['stage'] not in ('pretrained_cls_attention','untrained_hidden_head')]
    if selected:
        fig,axes=plt.subplots(1,2,figsize=(12,5))
        for ax,key in zip(axes,('mrr','auroc')):
            usable=[r for r in selected if r[key]]
            ax.bar([r['experiment'] for r in usable],[float(r[key]) for r in usable])
            ax.set(title='Test '+key,ylim=(0,1));ax.tick_params(axis='x',rotation=60)
        fig.tight_layout();fig.savefig(root/'comparison.png');plt.close(fig)


if __name__=='__main__': main()

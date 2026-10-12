"""Figure-6-style line Hit@fraction, not a basic-block or five-fold reproduction."""
import argparse
import csv
import json
import math
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from transformers import AutoTokenizer
from tqdm import tqdm
from data import load_unified_records, fingerprint, map_tokens_to_lines, changed_vulnerable_lines
from core.evaluation import random_ranking_metrics


def curve(rows):
    result=[]
    for fraction in [i/20 for i in range(2,21)]:
        hits=0; random_sum=0.; inspected=0
        for row in rows:
            n,m,rank=row['valid_lines'],row['positive_lines'],row['first_positive_rank']
            k=min(n,math.ceil(fraction*n))
            hits += rank <= k
            inspected += k
            miss=1.
            for j in range(min(k,n-m+1)):
                miss *= (n-m-j)/(n-j)
            random_sum += 1-miss
        result.append(dict(fraction=fraction,pairs=len(rows),hits=hits,hit_rate=hits/len(rows),
                           random_hit_rate=random_sum/len(rows),mean_inspected_lines=inspected/len(rows)))
    return result


def write_csv(path, rows):
    with path.open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)


def plot(path,series,split):
    fig,ax=plt.subplots(figsize=(8,5))
    for name,values in series:
        ax.plot([r['fraction'] for r in values],[r['hit_rate'] for r in values],marker='o',label=name)
        ax.plot([r['fraction'] for r in values],[r['random_hit_rate'] for r in values],'--',alpha=.6,label=f'Random: {name}')
    ax.set(xlabel='Fraction of valid lines inspected (top-ranked)',ylabel='Functions with >=1 proxy-line hit',
           title=f'Figure-6-style line localization | {split}, N={series[0][1][0]["pairs"]}\nChanged/deleted-line labels; conservative ties',
           xlim=(.1,1),ylim=(0,1.02))
    ax.grid(alpha=.25);ax.legend(fontsize=8)
    fig.tight_layout();fig.savefig(path.with_suffix('.png'),dpi=180);fig.savefig(path.with_suffix('.pdf'));plt.close(fig)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs',nargs='+',type=Path,required=True)
    parser.add_argument('--dataset',nargs='+',default=['../neuron/dataset/review/dataset.jsonl'])
    parser.add_argument('--split',choices=['validation','test'],default='test')
    parser.add_argument('--output-dir',type=Path,default=Path('outputs/figure6_comparison'))
    args=parser.parse_args()
    records=[pair for path in args.dataset for pair in load_unified_records(path)]
    digest=fingerprint(records)
    tokenizers={}; counts_cache={}; experiments=[]
    for run in args.runs:
        metadata=json.loads((run/'run.json').read_text())
        if metadata['dataset_sha256'] != digest: raise ValueError(f'Dataset/order mismatch: {run}')
        key=(metadata['model_id'],metadata['revision'])
        if key not in tokenizers:
            tokenizers[key]=AutoTokenizer.from_pretrained(key[0],revision=key[1],use_fast=True,local_files_only=True)
        tokenizer=tokenizers[key]
        with (run/args.split/'localization.csv').open() as f: saved=list(csv.DictReader(f))
        split_ids=set(json.loads((run/'splits.json').read_text())[args.split])
        rows=[];seen=set()
        for row in tqdm(saved,desc=run.name):
            index=int(row['pair'])
            if index in seen or index not in split_ids: raise ValueError('Duplicate or wrong-split pair')
            seen.add(index)
            cache_key=(key,index)
            if cache_key not in counts_cache:
                before,after=(s['code'] for s in records[index])
                encoded=tokenizer(before,return_offsets_mapping=True,truncation=False,verbose=False)
                valid=set(map_tokens_to_lines(before,encoded['offset_mapping']).values())-{-1}
                positive=changed_vulnerable_lines(before,after)&valid
                counts_cache[cache_key]=(len(valid),len(positive),len(encoded['input_ids']))
            n,m,tokens=counts_cache[cache_key]
            if tokens>metadata['arguments']['max_length'] or not m: raise ValueError('Invalid/overlength function')
            expected=random_ranking_metrics(n,m)
            for metric in ('hit_at_1','hit_at_5','mrr'):
                if not math.isclose(expected[metric],float(row['random_'+metric]),abs_tol=1e-9):
                    raise ValueError('Tokenizer/candidate-line mismatch')
            rr=float(row['mrr']);rank=round(1/rr)
            if not 1<=rank<=n or not math.isclose(rr,1/rank,abs_tol=1e-12): raise ValueError('Invalid reciprocal rank')
            rows.append(dict(pair=index,valid_lines=n,positive_lines=m,first_positive_rank=rank))
        if not rows: raise ValueError('No localization results')
        experiments.append((run,rows))
    common=set.intersection(*({r['pair'] for r in rows} for _,rows in experiments))
    if not common: raise ValueError('No shared pairs')
    all_curves=[];series=[]
    for run,rows in experiments:
        output=run/'figure6_style';output.mkdir(exist_ok=True)
        values=curve(rows)
        write_csv(output/f'{args.split}_curve.csv',values)
        write_csv(output/f'{args.split}_ranks.csv',rows)
        plot(output/args.split,[(run.name,values)],args.split)
        values=curve([r for r in rows if r['pair'] in common])
        series.append((run.name,values))
        all_curves.extend(dict(experiment=run.name,**r) for r in values)
    output=args.output_dir;output.mkdir(parents=True,exist_ok=True)
    write_csv(output/f'{args.split}_comparison.csv',all_curves)
    plot(output/f'{args.split}_comparison',series,args.split)
    (output/'definition.json').write_text(json.dumps(dict(
        dataset_sha256=digest,split=args.split,runs=[str(p) for p in args.runs],common_pairs=len(common),
        metric='Fraction of functions with >=1 changed/deleted proxy line among top ceil(fraction * valid_lines)',
        ties='Nonpositive lines first on equal score; recovered from saved MRR',
        caveats=['No basic-block labels','No cross-validation folds','Not an exact reproduction of paper Figure 6',
                 'Different models and training methods; not a controlled same-encoder ablation'],
        paper='https://arxiv.org/abs/2512.19758'),indent=2))
    print(f'Plots and CSV: {output}')


if __name__=='__main__': main()

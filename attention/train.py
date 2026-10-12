"""Function classification with optional patch-derived CLS attention supervision."""
import argparse
import csv
from datetime import datetime
from functools import partial
import hashlib
import json
import math
import os
from pathlib import Path
import random
import sys
import time
from zoneinfo import ZoneInfo

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import torch
from sklearn.metrics import roc_auc_score, average_precision_score, balanced_accuracy_score, roc_curve, confusion_matrix
from torch.utils.data import DataLoader
from transformers import AutoTokenizer, AutoConfig
from tqdm import tqdm
from model import MODELS, load_model, line_distribution, rationale_loss
from data import prepare, collate
from stopping import EarlyStopping
from core.evaluation import localization_metrics, random_ranking_metrics


def write_csv(path, rows):
    if not rows:
        return
    with Path(path).open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)


def seed_all(seed):
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def evaluate(model, loader, device, output=None, classification=True):
    model.eval()
    predictions, localization, examples = [], [], []
    with torch.inference_mode():
        for inputs, rows in tqdm(loader, desc='Evaluate', leave=False):
            logits, attention = model({k:v.to(device) for k,v in inputs.items()})
            probabilities = logits.float().softmax(-1)[:, 1].cpu().tolist()
            for row, att, prob in zip(rows, attention, probabilities):
                predictions.append(dict(pair=row['pair'], label=row['label'], probability=prob))
                if row['label'] != 1 or not row['positive']:
                    continue
                ids = torch.tensor(row['line_ids'], device=att.device)
                scores = line_distribution(att[:len(ids)], ids, logits=model.scoring == "hidden").cpu().tolist()
                metrics = localization_metrics(dict(enumerate(scores)), set(row['positive']))
                baseline = random_ranking_metrics(len(scores), len(row['positive']))
                localization.append(dict(pair=row['pair'], **metrics, **{'random_'+k:v for k,v in baseline.items()}))
                if len(examples) < 6:
                    examples.append((row, scores))
    result = dict(functions=len(predictions), localization_pairs=len(localization))
    for key in ('hit_at_1', 'hit_at_5', 'mrr', 'random_hit_at_1', 'random_hit_at_5', 'random_mrr'):
        result[key] = float(np.mean([r[key] for r in localization])) if localization else None
    y = [r['label'] for r in predictions]
    p = [r['probability'] for r in predictions]
    result.update(auroc=roc_auc_score(y,p) if classification else None,
                  auprc=average_precision_score(y,p) if classification else None,
                  balanced_accuracy=balanced_accuracy_score(y, np.asarray(p)>=.5) if classification else None)
    if output:
        output.mkdir(parents=True, exist_ok=True)
        if classification:
            write_csv(output/'function_predictions.csv', predictions)
            fig, axes = plt.subplots(1, 2, figsize=(9,4))
            fpr,tpr,_ = roc_curve(y,p)
            axes[0].plot(fpr,tpr,label=f'AUROC={result["auroc"]:.3f}')
            axes[0].plot([0,1],[0,1],'--',color='gray'); axes[0].legend()
            axes[0].set(xlabel='False positive rate',ylabel='True positive rate')
            cm = confusion_matrix(y,np.asarray(p)>=.5,labels=[0,1])
            axes[1].imshow(cm,cmap='Blues')
            for (a,b), value in np.ndenumerate(cm): axes[1].text(b,a,str(value),ha='center',va='center')
            axes[1].set(xticks=[0,1],yticks=[0,1],xlabel='Predicted',ylabel='True',title='Threshold 0.5')
            fig.tight_layout(); fig.savefig(output/'classification.png'); plt.close(fig)
        write_csv(output/'localization.csv', localization)
        if examples:
            fig, axes = plt.subplots(len(examples),1,figsize=(11,2.5*len(examples)),squeeze=False)
            line_rows = []
            for ax,(row,scores) in zip(axes[:,0],examples):
                lines = [q+1 for q in row['source_lines']]
                ax.bar(lines,scores,color=['tomato' if j in row['positive'] else 'steelblue' for j in range(len(scores))])
                ax.set(title=f'Pair {row["pair"]}: red = changed/deleted proxy',xlabel='Source line (1-based)',ylabel='Line probability')
                line_rows.extend(dict(pair=row['pair'],line=q,score=s,proxy_positive=int(j in row['positive'])) for j,(q,s) in enumerate(zip(lines,scores)))
            fig.tight_layout(); fig.savefig(output/'line_scores.png'); plt.close(fig)
            write_csv(output/'line_scores.csv', line_rows)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', nargs='+', default=['../neuron/dataset/review/dataset.jsonl'])
    parser.add_argument('--reference-models', help='Optional ALL inference_models.joblib to reproduce existing splits')
    parser.add_argument('--model', choices=list(MODELS), default='modernbert')
    parser.add_argument('--mode', choices=['classification','rationale','random','hidden'], default='classification')
    parser.add_argument('--max-length',type=int,default=8192)
    parser.add_argument('--epochs',type=int,default=100)
    parser.add_argument('--patience',type=int,default=5, help='Epochs without sufficient validation improvement; 0 disables stopping')
    parser.add_argument('--min-delta',type=float,default=.001)
    parser.add_argument('--batch-size',type=int,default=1)
    parser.add_argument('--accumulation',type=int,default=16)
    parser.add_argument('--lr',type=float,default=2e-5)
    parser.add_argument('--attention-weight',type=float,default=.1)
    parser.add_argument('--seed',type=int,default=42)
    parser.add_argument('--cpu-threads',type=int,default=4)
    parser.add_argument('--select-by',choices=['mrr','auroc'],default='mrr')
    parser.add_argument('--output-dir',type=Path)
    args=parser.parse_args()
    if min(args.epochs,args.batch_size,args.accumulation,args.max_length,args.cpu_threads)<1 or args.lr<=0 or args.attention_weight<0:
        parser.error('Invalid positive counts/learning rate or negative attention weight')
    if args.patience < 0 or not math.isfinite(args.min_delta) or args.min_delta < 0:
        parser.error('patience and min-delta must be nonnegative and finite')
    torch.set_num_threads(args.cpu_threads); seed_all(args.seed)
    model_id=MODELS[args.model]
    config=AutoConfig.from_pretrained(model_id)
    capacity=config.max_position_embeddings - (config.pad_token_id+1 if config.model_type=='roberta' else 0)
    if args.max_length>capacity: parser.error(f'{args.model} max-length must be <= {capacity}')
    revision=getattr(config,'_commit_hash',None) or 'main'
    tokenizer=AutoTokenizer.from_pretrained(model_id,revision=revision,use_fast=True)
    output=args.output_dir or Path('outputs')/f'{args.model}_{args.mode}_{datetime.now(ZoneInfo("Asia/Taipei")):%Y%m%d_%H%M%S_%f}'
    output.mkdir(parents=True,exist_ok=True)
    if (output/'run.json').exists():
        raise ValueError('Output already exists; use a new directory (do not overwrite experiments)')
    examples,metadata=prepare(args,tokenizer)
    for split,rows in examples.items():
        if not rows: raise ValueError(f'No retained {split} examples')
    if args.select_by=='mrr' and not any(r['positive'] for r in examples['validation']):
        raise ValueError('No validation localization labels; select-by auroc instead')
    if args.mode!='classification' and not any(r['positive'] for r in examples['train']):
        raise ValueError('Attention supervision requires train rationales')
    with (output/'splits.json').open('w') as f: json.dump(metadata.pop('splits'),f)
    write_csv(output/'data_counts.csv',[dict(split=k,**v) for k,v in metadata['counts'].items()])
    loaders={s:DataLoader(rows,batch_size=args.batch_size,shuffle=False,collate_fn=partial(collate,tokenizer=tokenizer)) for s,rows in examples.items()}
    device='cuda' if torch.cuda.is_available() else 'cpu'
    if os.environ.get('ATTENTION_REQUIRE_CUDA') == '1' and device != 'cuda':
        raise RuntimeError('Assigned GPU is unavailable; refusing to silently train on CPU')
    model=load_model(args.model,revision,scoring="hidden" if args.mode == "hidden" else "attention").to(device)
    run=dict(arguments={k:str(v) if isinstance(v,Path) else v for k,v in vars(args).items()},
             **metadata,model_id=model_id,revision=revision,device=device,attention_layer=model.attention_layer,
             attention='mean heads of selected global CLS query; pre-dropout; mean token score per line, renormalized over code lines',
             line_scoring=('final hidden states: mean tokens per line -> linear head -> softmax across valid lines'
                           if args.mode == 'hidden' else 'CLS attention'),
             target='uniform probability over vulnerable changed/deleted lines; no patched rationale loss',
             random_control='same line count; prefer non-rationale lines; fixed per pair; NOT token-length matched',
             threshold=.5,versions={'torch':torch.__version__},
             source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')})
    import transformers
    run['versions']['transformers']=transformers.__version__
    (output/'run.json').write_text(json.dumps(run,indent=2))
    print(f'Device={device}; attention layer={model.attention_layer}; output={output}',flush=True)
    report=[]
    # Untrained classification head has no meaningful function predictions.
    for split in ('validation','test'):
        score=evaluate(model,loaders[split],device,output/('pretrained_'+split),classification=False)
        report.append(dict(stage='untrained_hidden_head' if args.mode == 'hidden' else 'pretrained_cls_attention',split=split,epoch=0,**score))
    write_csv(output/'report.csv',report)
    balance=0.
    if args.mode!='classification':
        # Estimate the fixed loss scale on train only, in eval mode (dropout disabled).
        rng=random.Random(args.seed)
        sample=rng.sample(examples['train'], min(len(examples['train']),128))
        ce,ar=[],[]
        model.eval()
        with torch.no_grad():
            for inputs,rows in DataLoader(sample,batch_size=args.batch_size,collate_fn=partial(collate,tokenizer=tokenizer)):
                logits,att=model({k:v.to(device) for k,v in inputs.items()})
                ce.append(torch.nn.functional.cross_entropy(logits,torch.tensor([r['label'] for r in rows],device=device)).item())
                ar.append(rationale_loss(att,rows,args.mode).item())
        if np.mean(ar)<=0: raise ValueError('No rationale loss in train calibration sample')
        balance=float(np.mean(ce)/np.mean(ar))
    run['loss_balance']=balance
    (output/'run.json').write_text(json.dumps(run,indent=2))
    optimizer=torch.optim.AdamW(model.parameters(),lr=args.lr,weight_decay=.01)
    history=[]; best=-math.inf
    stopping=EarlyStopping(args.patience,args.min_delta)
    stop_reason="max_epochs"
    for epoch in range(1,args.epochs+1):
        generator=torch.Generator().manual_seed(args.seed+epoch)
        loader=DataLoader(examples['train'],batch_size=args.batch_size,shuffle=True,generator=generator,collate_fn=partial(collate,tokenizer=tokenizer))
        seed_all(args.seed+epoch); model.train(); optimizer.zero_grad()
        totals=np.zeros(3); start=time.monotonic()
        for step,(inputs,rows) in enumerate(tqdm(loader,desc=f'{args.mode} epoch {epoch}')):
            logits,attention=model({k:v.to(device) for k,v in inputs.items()})
            ce=torch.nn.functional.cross_entropy(logits,torch.tensor([r['label'] for r in rows],device=device))
            ar=rationale_loss(attention,rows,args.mode) if args.mode!='classification' else attention.sum()*0
            loss=ce+args.attention_weight*balance*ar
            if not torch.isfinite(loss): raise ValueError('Nonfinite training loss')
            group_start=(step//args.accumulation)*args.accumulation
            divisor=min(args.accumulation,len(loader)-group_start)
            (loss/divisor).backward()
            if (step+1)%args.accumulation==0 or step+1==len(loader):
                torch.nn.utils.clip_grad_norm_(model.parameters(),1.)
                optimizer.step(); optimizer.zero_grad()
            totals += [loss.item(),ce.item(),ar.item()]
        metrics=evaluate(model,loaders['validation'],device)
        value=metrics[args.select_by]
        should_stop=stopping.update(value)
        history.append(dict(epoch=epoch,stale_epochs=stopping.stale,stopping_reference=stopping.reference,loss=totals[0]/len(loader),classification_loss=totals[1]/len(loader),
                            attention_loss=totals[2]/len(loader),seconds=time.monotonic()-start,**metrics))
        write_csv(output/'history.csv',history)
        print(json.dumps(history[-1]),flush=True)
        if metrics[args.select_by]>best:
            best=metrics[args.select_by]
            torch.save(dict(state_dict=model.state_dict(),epoch=epoch,model_id=model_id,revision=revision,
                            attention_layer=model.attention_layer,scoring=model.scoring,mode=args.mode),output/'best.pt')
        if should_stop:
            stop_reason="early_stopping"
            print(f"Early stopping at epoch {epoch}: {args.select_by} did not improve by more than {args.min_delta} for {args.patience} epochs",flush=True)
            break
    checkpoint=torch.load(output/'best.pt',map_location=device,weights_only=True)
    model.load_state_dict(checkpoint['state_dict']); del checkpoint['state_dict']
    for split in ('validation','test'):
        metrics=evaluate(model,loaders[split],device,output/split)
        report.append(dict(stage=args.mode,split=split,epoch=checkpoint['epoch'],**metrics))
    write_csv(output/'report.csv',report)
    fig,axes=plt.subplots(1,2,figsize=(10,4))
    for key in ('loss','classification_loss','attention_loss'):
        axes[0].plot([r['epoch'] for r in history],[r[key] for r in history],label=key)
    for key in ('mrr','auroc'):
        axes[1].plot([r['epoch'] for r in history],[r[key] for r in history],label='validation '+key)
    for ax in axes: ax.set_xlabel('Epoch'); ax.legend()
    fig.tight_layout();fig.savefig(output/'training.png');plt.close(fig)
    (output/'complete.json').write_text(json.dumps(dict(best_epoch=checkpoint['epoch'],best_validation_score=best,
        stopped_epoch=epoch,stop_reason=stop_reason,select_by=args.select_by,
        patience=args.patience,min_delta=args.min_delta,stale_epochs=stopping.stale)))
    print(f'Completed: {output}',flush=True)


if __name__=='__main__': main()

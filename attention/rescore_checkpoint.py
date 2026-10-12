"""Re-run trained checkpoints: all-layer incoming attention sum and CLS line mean.

Incoming attention matches neuron/attention_baseline.py ranking (the omitted
layer-count divisor is constant per function). This is an Eq.4 adaptation,
not the paper's full CFG/basic-block experiment.
"""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import torch
from transformers import AutoTokenizer
from tqdm import tqdm
from model import LEGACY, load_model, line_distribution
from data import load_unified_records, fingerprint
from core.mapper import prepare_code_input
from core.evaluation import changed_vulnerable_lines, localization_metrics, random_ranking_metrics
from plot_top_fraction import curve, plot, write_csv


def incoming_weights(query, key, mask, chunk_size=128):
    """Exact pre-dropout incoming probabilities, with bounded query-row memory."""
    total=key.new_zeros((key.shape[0],key.shape[-2]),dtype=torch.float32)
    for start in range(0,query.shape[-2],chunk_size):
        logits=query[:,:,start:start+chunk_size].float() @ key.float().transpose(-1,-2)
        logits *= query.shape[-1] ** -.5
        if mask is not None:
            block=mask if mask.shape[-2]==1 else mask[...,start:start+chunk_size,:]
            logits=logits.masked_fill(~block,float('-inf')) if block.dtype==torch.bool else logits+block
        total += logits.softmax(-1).mean(1).sum(1)
    return total


class IncomingCollector:
    def __init__(self,encoder,chunk_size):
        self.total=None
        self.count=0
        self.chunk_size=chunk_size
        self.hooks=[]
        layers=encoder.layers if encoder.config.model_type=='modernbert' else encoder.encoder.layer
        self.expected=len(layers)
        for layer in layers:
            module=layer.attn if encoder.config.model_type=='modernbert' else layer.attention.self
            self.hooks.append(module.register_forward_pre_hook(self.collect,with_kwargs=True))

    def collect(self,module,args,kwargs):
        hidden=args[0] if args else kwargs['hidden_states']
        mask=kwargs.get('attention_mask')
        if hasattr(module,'Wqkv'):
            from transformers.models.modernbert.modeling_modernbert import apply_rotary_pos_emb
            heads=module.num_heads if LEGACY else module.config.num_attention_heads
            qkv=module.Wqkv(hidden).view(hidden.shape[0],-1,3,heads,module.head_dim)
            query,key,_=qkv.transpose(3,1).unbind(dim=2)
            if LEGACY:
                cos,sin=module.rotary_emb(qkv,position_ids=kwargs['position_ids'])
                if module.local_attention!=(-1,-1): mask=kwargs['sliding_window_mask']
            else:
                cos,sin=kwargs['position_embeddings']
            query,key=apply_rotary_pos_emb(query,key,cos,sin)
        else:
            shape=(*hidden.shape[:-1],module.num_attention_heads,module.attention_head_size)
            query=module.query(hidden).view(shape).transpose(1,2)
            key=module.key(hidden).view(shape).transpose(1,2)
        values=incoming_weights(query,key,mask,self.chunk_size)[0].cpu()
        self.total=values if self.total is None else self.total+values
        self.count+=1

    def clear(self): self.total=None;self.count=0
    def close(self):
        for hook in self.hooks: hook.remove()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,required=True)
    parser.add_argument('--dataset',nargs='+',default=['../neuron/dataset/review/dataset.jsonl'])
    parser.add_argument('--split',choices=['test','validation'],default='test')
    parser.add_argument('--cpu-threads',type=int,default=4)
    parser.add_argument('--chunk-size',type=int,default=128)
    parser.add_argument('--device',choices=['auto','cpu','cuda'],default='auto')
    args=parser.parse_args()
    if args.cpu_threads<1 or args.chunk_size<1: parser.error('Thread and chunk counts must be positive')
    torch.set_num_threads(args.cpu_threads)
    run=json.loads((args.run/'run.json').read_text())
    records=[p for path in args.dataset for p in load_unified_records(path)]
    if fingerprint(records)!=run['dataset_sha256']: raise ValueError('Dataset/order mismatch')
    with (args.run/args.split/'localization.csv').open() as stream:
        indices=[int(r['pair']) for r in csv.DictReader(stream)]
    if len(set(indices))!=len(indices): raise ValueError('Duplicate pair indices')
    split_ids=set(json.loads((args.run/'splits.json').read_text())[args.split])
    if not set(indices)<=split_ids: raise ValueError('Wrong split')
    checkpoint=torch.load(args.run/'best.pt',map_location='cpu',weights_only=True)
    if checkpoint['model_id']!=run['model_id'] or checkpoint['revision']!=run['revision']:
        raise ValueError('Checkpoint metadata mismatch')
    if checkpoint.get('scoring','attention')!='attention': raise ValueError('Expected attention classifier checkpoint')
    output=args.run/'attention_rescore'/args.split
    output.mkdir(parents=True,exist_ok=True)
    digest=hashlib.sha256()
    with (args.run/'best.pt').open('rb') as stream:
        for block in iter(lambda:stream.read(8*1024*1024),b''): digest.update(block)
    manifest=dict(checkpoint_sha256=digest.hexdigest(),dataset_sha256=run['dataset_sha256'],
                  split=args.split,epoch=checkpoint['epoch'],indices=indices,
                  incoming='sum layers / mean heads / sum queries / sum tokens per line; special queries included',
                  cls='selected global layer CLS attention / mean heads / mean tokens per line',
                  labels='changed/deleted proxy lines; no CFG/basic blocks; no cross-validation',version=1)
    path=output/'run.json'
    if path.exists() and json.loads(path.read_text())!=manifest: raise ValueError('Existing rescore belongs to different checkpoint/data')
    path.write_text(json.dumps(manifest,indent=2))
    progress=output/'progress.jsonl'
    rows=[json.loads(line) for line in progress.read_text().splitlines()] if progress.exists() else []
    done={r['pair'] for r in rows}
    if len(done)!=len(rows) or not done<=set(indices): raise ValueError('Invalid progress file')
    pending=[i for i in indices if i not in done]
    tokenizer=AutoTokenizer.from_pretrained(run['model_id'],revision=run['revision'],use_fast=True,local_files_only=True)
    device=('cuda' if torch.cuda.is_available() else 'cpu') if args.device=='auto' else args.device
    if pending:
        print(f'Device={device}; pending={len(pending)}; output={output}',flush=True)
        model=load_model(run['arguments']['model'],run['revision']).to(device).eval()
        model.load_state_dict(checkpoint['state_dict'],strict=True)
        del checkpoint
        collector=IncomingCollector(model.encoder,args.chunk_size)
        try:
            with progress.open('a') as stream,torch.inference_mode():
                for i in tqdm(pending,desc='Re-score',initial=len(done),total=len(indices)):
                    before,after=(side['code'] for side in records[i])
                    inputs,mapping,valid,truncated=prepare_code_input(before,tokenizer,run['arguments']['max_length'])
                    positive=changed_vulnerable_lines(before,after)&valid
                    if truncated or not positive: raise ValueError('Invalid saved evaluation cohort')
                    collector.clear()
                    logits,cls=model({k:v.to(device) for k,v in inputs.items()})
                    if collector.count!=collector.expected: raise ValueError('Missing attention layers')
                    order=sorted(valid); compact={q:j for j,q in enumerate(order)}
                    ids=torch.tensor([compact.get(mapping[t],-1) for t in range(len(mapping))],device=cls.device)
                    cls_scores=line_distribution(cls[0],ids).cpu().tolist()
                    incoming={q:0. for q in valid}
                    for t,q in mapping.items():
                        if q in valid: incoming[q]+=float(collector.total[t])
                    row=dict(pair=i,lines=order,positive=sorted(positive),
                             incoming=[incoming[q] for q in order],cls=cls_scores,
                             vulnerable_probability=float(logits.softmax(-1)[0,1]))
                    if not all(math.isfinite(s) for name in ('incoming','cls') for s in row[name]): raise ValueError('Nonfinite scores')
                    stream.write(json.dumps(row)+'\n');stream.flush();rows.append(row)
        finally: collector.close()
    export(output,rows)
    print(f'Completed re-scoring: {output}',flush=True)


def export(output,rows):
    report=[];series=[];details=[]
    for method in ('incoming','cls'):
        ranks=[];metrics=[]
        for row in rows:
            scores=dict(zip(row['lines'],row[method]))
            result=localization_metrics(scores,set(row['positive']))
            metrics.append(dict(pair=row['pair'],**result))
            ranks.append(dict(valid_lines=len(scores),positive_lines=len(row['positive']),first_positive_rank=round(1/result['mrr'])))
            details.extend(dict(method=method,pair=row['pair'],line=q+1,score=s,proxy_positive=int(q in row['positive'])) for q,s in scores.items())
        report.append(dict(method=method,pairs=len(rows),**{k:sum(r[k] for r in metrics)/len(metrics) for k in ('hit_at_1','hit_at_5','mrr')}))
        write_csv(output/f'{method}_localization.csv',metrics)
        values=curve(ranks);write_csv(output/f'{method}_curve.csv',values);series.append((method,values))
    write_csv(output/'line_scores.csv',details)
    write_csv(output/'report.csv',report)
    plot(output/'figure6_style',series,output.name)


if __name__=='__main__': main()

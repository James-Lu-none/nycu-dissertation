"""Fixed synthetic boundary-error controls; no fitting or example selection."""
import argparse
import csv
import json
from pathlib import Path

import torch
from transformers import AutoTokenizer
from model import load_model, line_distribution
from rescore_checkpoint import IncomingCollector
from core.mapper import prepare_code_input

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', default='cpu')
    parser.add_argument('--local-files-only', action='store_true')
    parser.add_argument('--output-dir', type=Path, default=ROOT/'outputs/synthetic_bounds')
    args = parser.parse_args()
    torch.set_num_threads(4)
    runs = {
        'A': ROOT/'outputs/pipeline_20261011_231355/securebert2_classification',
        'B': ROOT/'outputs/pipeline_20261012_231316/modernbert_classification',
        'C': ROOT/'outputs/pipeline_20261012_231316/modernbert_rationale',
    }
    results = {}; summary = []; metadata = {}
    for method, run in runs.items():
        info = json.loads((run/'run.json').read_text())
        checkpoint = torch.load(run/'best.pt', map_location='cpu', weights_only=True)
        tokenizer = AutoTokenizer.from_pretrained(info['model_id'], revision=info['revision'], use_fast=True,
                                                 local_files_only=args.local_files_only)
        model = load_model(info['arguments']['model'], info['revision'], local_files_only=args.local_files_only)
        model.load_state_dict(checkpoint['state_dict'], strict=True)
        del checkpoint
        model.to(args.device).eval()
        collector = IncomingCollector(model.encoder, 128) if method == 'A' else None
        metadata[method] = dict(run=str(run), model=info['model_id'], revision=info['revision'])
        try:
            for path in sorted((ROOT/'examples/synthetic_bounds').glob('*.c')):
                code = path.read_text(); lines = code.split('\n')
                inputs, mapping, valid, truncated = prepare_code_input(code, tokenizer, info['arguments']['max_length'])
                if truncated:
                    raise ValueError('Synthetic input was truncated')
                if collector: collector.clear()
                with torch.inference_mode():
                    logits, attention = model({k:v.to(args.device) for k,v in inputs.items()})
                order = sorted(valid)
                if collector:
                    if collector.count != collector.expected: raise ValueError('Missing attention layers')
                    values = torch.tensor([sum(float(collector.total[t]) for t,q in mapping.items() if q==line) for line in order])
                    values /= values.sum()
                else:
                    compact = {q:j for j,q in enumerate(order)}
                    ids = torch.tensor([compact.get(mapping[t], -1) for t in range(len(mapping))], device=args.device)
                    values = line_distribution(attention[0], ids).cpu()
                scores = dict(zip(order, values.tolist()))
                results.setdefault(path.stem, dict(code=lines, scores={} ))['scores'][method] = scores
                ranked = sorted(scores, key=lambda q:(-scores[q], q))
                sink = next(q for q,s in enumerate(lines) if "buffer[len] =" in s)
                guard = next(q for q,s in enumerate(lines) if 'if (len ' in s)
                summary.append(dict(sample=path.stem, method=method,
                                    function_probability=float(logits.softmax(-1)[0,1]),
                                    top_line=ranked[0]+1, guard_rank=ranked.index(guard)+1,
                                    write_rank=ranked.index(sink)+1, write_score=scores[sink]))
                print(summary[-1], flush=True)
        finally:
            if collector: collector.close()
        del model
    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows=[]; text=['A: incoming attention (SecureBERT2); B: CLS classification; C: CLS rationale (ModernBERT).\nNormalized line scores, not vulnerability probabilities.\n']
    for name, result in results.items():
        text.append(f'\n{name}\nLine |     A      |     B      |     C      | Code\n')
        for q, code in enumerate(result['code']):
            scores={m:result['scores'][m].get(q) for m in runs}
            text.append(f'{q+1:4d} | '+' | '.join(f'{s:10.6f}' if s is not None else '        NA' for s in scores.values())+f' | {code}\n')
            rows.append(dict(sample=name,line=q+1,**scores,code=code))
    for name, data in [('line_scores.csv', rows), ('summary.csv', summary)]:
        with (args.output_dir/name).open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=list(data[0]));writer.writeheader();writer.writerows(data)
    (args.output_dir/'code_scores.txt').write_text(''.join(text))
    (args.output_dir/'run.json').write_text(json.dumps(dict(models=metadata,device=args.device,
        controls='Same guard/write positions; plain versus safe-code/comment distractors; > versus >= patch',
        assumptions='src references at least len readable bytes; no concurrency; defect is buffer[32] write at len=32',
        caveat='Four hand-written diagnostics, not a generalization benchmark; no sample tuning after scoring'),indent=2))


if __name__ == '__main__': main()

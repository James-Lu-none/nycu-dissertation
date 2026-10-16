"""Scan source trees, score complete functions, and map scores to bench slice lines.

Sources must be prepared using the benchmark download scripts. No DFG input is modified.
"""
import argparse
import csv
import hashlib
import json
import re
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_csv(path, rows, fields):
    with path.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader(); writer.writerows(rows)


def function_name(node, data):
    declarator = node.child_by_field_name('declarator')
    while declarator is not None:
        if declarator.type in ('identifier', 'field_identifier', 'qualified_identifier', 'operator_name', 'destructor_name'):
            return data[declarator.start_byte:declarator.end_byte].decode('utf-8', errors='replace')
        child = declarator.child_by_field_name('declarator')
        if child is None and declarator.type == 'parenthesized_declarator':
            child = next(iter(declarator.named_children), None)
        declarator = child
    return None


def valid_function_boundary(node, data):
    body=node.child_by_field_name('body')
    decl=node.child_by_field_name('declarator')
    if body is None or decl is None or decl.has_error or body.type!='compound_statement':return False
    if any(child.has_error for child in node.named_children if child != body):return False
    text=data[body.start_byte:body.end_byte].decode('utf-8')
    # Ignore comments and literals; require exactly one balanced outer brace pair.
    stripped=re.sub(r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '', text)
    braces=[c for c in stripped if c in '{}'];depth=0
    if not braces or braces[0]!='{' or braces[-1]!='}':return False
    for i,c in enumerate(braces):
        depth += 1 if c=='{' else -1
        if depth<0 or (depth==0 and i!=len(braces)-1):return False
    return depth==0


def scan_tree(root, paths=None):
    from importlib.metadata import version
    if version('tree-sitter') != '0.25.2':
        raise RuntimeError('Install requirements-bench.txt: tree-sitter 0.26 crashes on these sources')
    from tree_sitter import Language, Parser
    import tree_sitter_c
    import tree_sitter_cpp
    parsers = {'c': Parser(Language(tree_sitter_c.language())), 'cpp': Parser(Language(tree_sitter_cpp.language()))}
    for parser in parsers.values():
        parser.timeout_micros = 2_000_000
    functions = []; files = []
    for path in sorted(root.rglob('*') if paths is None else paths):
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in ('.c', '.h', '.cc', '.cpp', '.cxx', '.hpp') or '.git' in path.parts:
            continue
        data = path.read_bytes(); rel = path.relative_to(root).as_posix()
        try: data.decode('utf-8')
        except UnicodeDecodeError:
            files.append(dict(file=rel,status='non_utf8',functions=0)); continue
        parser = parsers['c' if path.suffix.lower() in ('.c', '.h') else 'cpp']
        try:
            tree = parser.parse(data)
        except ValueError:
            parser.reset()
            files.append(dict(file=rel,status='parse_timeout',functions=0)); continue
        stack = [tree.root_node]; count = 0
        while stack:
            node = stack.pop()
            if node.type != 'function_definition':
                stack.extend(reversed(node.named_children)); continue
            name = function_name(node, data)
            start, end = node.start_point.row, node.end_point.row
            # Preserve line/column alignment but exclude code outside the function on boundary lines.
            code = ' '*node.start_point.column + data[node.start_byte:node.end_byte].decode('utf-8')
            fid = sha(code.encode())
            boundary_ok=bool(name) and (not node.has_error or valid_function_boundary(node,data))
            functions.append(dict(file=rel,name=name or '',start=start+1,end=end+1,
                                  status='ok' if boundary_ok else 'parse_error',
                                  parse_warning=bool(node.has_error),code=code,code_sha256=fid))
            count += 1
        files.append(dict(file=rel,status='file_has_parse_errors' if tree.root_node.has_error else 'ok',functions=count))
        if len(files)%500==0:print(f'  {root.name}: scanned {len(files)} files',flush=True)
    return functions, files


def file_matches(request, actual):
    return actual == request or actual.endswith('/'+request)


def locate(functions, filename, line=None, name=None):
    if isinstance(functions, dict):
        functions = functions.get(Path(filename).name, [])
    hits = [f for f in functions if file_matches(filename, f['file']) and
            (line is None or f['start'] <= line <= f['end']) and (name is None or f['name'] == name)]
    if not hits: return None, 'unresolved_function'
    if len(hits) != 1: return None, 'ambiguous_function'
    return hits[0], hits[0]['status']


def generate_bfd_sources(root):
    """Apply the release Makefile's literal substitutions, preserving line numbers."""
    template=root/'bfd/peXXigen.c';recipe=root/'bfd/Makefile.am'
    created=[]
    if template.exists() and recipe.exists():
        for prefix in ('pe','pep','pex64'):
            target=root/'bfd'/f'{prefix}igen.c'
            if not target.exists() and f'-e s/XX/{prefix}/g' in recipe.read_text():
                target.write_bytes(template.read_bytes().replace(b'XX',prefix.encode()))
                created.append(target)
    return created


def prepare(args):
    sources = json.loads(args.sources.read_text()); projects = {}; candidates = {}; catalogs = {}
    output = args.output_dir; output.mkdir(parents=True, exist_ok=True)
    for source in sources:
        if source['status'] != 'ready':
            for project in source['projects']: projects[project] = dict(status='source_unavailable',targets=[],functions=[])
            continue
        root = Path(source['roots'][0])
        generate_bfd_sources(root)
        functions, files = scan_tree(root)
        by_file = defaultdict(list)
        for f in functions:by_file[Path(f['file']).name].append(f)
        catalogs[source['key']] = dict(root=str(root),files=files,functions=[{k:v for k,v in f.items() if k!='code'} for f in functions])
        print(f'Scanned {root.name}: {len(files)} files / {len(functions)} functions', flush=True)
        if args.scope == 'all':
            for f in functions:
                if f['status']=='ok': candidates[f['code_sha256']] = f['code']
        for project in source['projects']:
            directory = args.bench/project; targets=[]; selected=[]
            for text in (directory/'slice_func.txt').read_text().splitlines():
                if not text.strip(): continue
                filename, name = text.strip().split(':',1)
                f,status = locate(by_file,filename,name=name)
                selected.append(dict(request=text,status=status,function=f['code_sha256'] if f else None))
                if f and status=='ok': candidates[f['code_sha256']]=f['code']
            for text in (directory/'slice_dfg.txt').read_text().splitlines():
                if not text.strip(): continue
                original, position = text.split(maxsplit=1);filename, number=position.rsplit(':',1);line=int(number)
                f,status = locate(by_file, filename,line=line)
                targets.append(dict(original_dfg_value=original,requested_file=filename,line=line,status=status,
                                    file=f['file'] if f else filename,function=f['name'] if f else '',
                                    function_start=f['start'] if f else None,code_sha256=f['code_sha256'] if f else None))
                if f and status=='ok': candidates[f['code_sha256']]=f['code']
            projects[project]=dict(status='ready',source_key=source['key'],targets=targets,functions=selected)
    (output/'catalog.json').write_text(json.dumps(catalogs,indent=2))
    (output/'mapping.json').write_text(json.dumps(projects,indent=2))
    with (output/'functions.jsonl').open('w') as stream:
        for fid,code in candidates.items(): stream.write(json.dumps(dict(code_sha256=fid,code=code))+'\n')
    (output/'sources.json').write_text(json.dumps(sources,indent=2))
    print(f'{len(projects)} projects; {len(candidates)} unique functions selected; scope={args.scope}',flush=True)
    return projects,candidates


def score(args, candidates):
    import numpy as np
    import torch
    import transformers
    from transformers import AutoTokenizer
    from model import load_model, line_distribution
    from rescore_checkpoint import IncomingCollector
    from core.mapper import prepare_code_input
    from tqdm import tqdm
    torch.set_num_threads(args.cpu_threads)
    device = ('cuda' if torch.cuda.is_available() else 'cpu') if args.device=='auto' else args.device
    db = sqlite3.connect(args.output_dir/'scores.sqlite')
    db.execute('CREATE TABLE IF NOT EXISTS scores (method TEXT, code TEXT, result TEXT, PRIMARY KEY(method,code))')
    keys = {}; manifests = {}; jobs = []
    for method, run in [('attention_distance',args.attention_run),('rationale',args.rationale_run)]:
        info = json.loads((run/'run.json').read_text())
        digest=hashlib.sha256()
        with (run/'best.pt').open('rb') as stream:
            for block in iter(lambda:stream.read(8*1024*1024),b''):digest.update(block)
        meta=dict(checkpoint_sha256=digest.hexdigest(),model=info['model_id'],revision=info['revision'],
                  max_length=info['arguments']['max_length'],scoring=method,version=1,
                  torch=torch.__version__,transformers=transformers.__version__,
                  implementation={p.name:sha(p.read_bytes()) for p in [Path(__file__),ROOT/'model.py',ROOT/'rescore_checkpoint.py',ROOT.parent/'neuron/core/mapper.py']})
        key=sha(json.dumps(meta,sort_keys=True).encode());keys[method]=key;manifests[method]=meta
        jobs.append((method,run,info,key))
    (args.output_dir/'models.json').write_text(json.dumps(dict(keys=keys,models=manifests),indent=2))
    for method,run,info,key in jobs:
        done={r[0] for r in db.execute('SELECT code FROM scores WHERE method=?',(key,))}
        pending=[fid for fid in candidates if fid not in done]
        print(f'{method}: {len(pending)} pending, device={device}',flush=True)
        if not pending:continue
        tokenizer=AutoTokenizer.from_pretrained(info['model_id'],revision=info['revision'],use_fast=True,local_files_only=args.local_files_only)
        model=load_model(info['arguments']['model'],info['revision'],local_files_only=args.local_files_only)
        checkpoint=torch.load(run/'best.pt',map_location='cpu',weights_only=True)
        if checkpoint['model_id']!=info['model_id'] or checkpoint['revision']!=info['revision']:raise ValueError('Checkpoint metadata mismatch')
        model.load_state_dict(checkpoint['state_dict'],strict=True);del checkpoint
        model.to(device).eval()
        collector=IncomingCollector(model.encoder,args.chunk_size) if method=='attention_distance' else None
        try:
            for fid in tqdm(pending,desc=method):
                code=candidates[fid]
                length=len(tokenizer(code,truncation=False,verbose=False)['input_ids'])
                result=dict(status='overlength',tokens=length)
                if length<=info['arguments']['max_length']:
                    inputs,mapping,valid,truncated=prepare_code_input(code,tokenizer,info['arguments']['max_length'])
                    if truncated:raise ValueError('Unexpected truncated function')
                    if collector:collector.clear()
                    with torch.inference_mode():logits,att=model({k:v.to(device) for k,v in inputs.items()})
                    order=sorted(valid)
                    if collector:
                        if collector.count!=collector.expected:raise ValueError('Incomplete attention capture')
                        raw=np.zeros(len(order));compact={q:j for j,q in enumerate(order)}
                        for t,q in mapping.items():
                            if q in compact:raw[compact[q]]+=float(collector.total[t])
                        values=raw/raw.sum()
                    else:
                        compact={q:j for j,q in enumerate(order)}
                        ids=torch.tensor([compact.get(mapping[t],-1) for t in range(len(mapping))],device=device)
                        values=line_distribution(att[0],ids).cpu().numpy();raw=values
                    if not np.isfinite(values).all():raise ValueError('Nonfinite scores')
                    result=dict(status='scored',tokens=length,lines=order,scores=values.tolist(),raw_scores=raw.tolist(),
                                function_probability=float(logits.softmax(-1)[0,1]))
                db.execute('INSERT OR REPLACE INTO scores VALUES (?,?,?)',(key,fid,json.dumps(result)));db.commit()
        finally:
            if collector:collector.close()
        del model
    db.close()


def export(args,projects):
    import numpy as np
    model_meta=json.loads((args.output_dir/'models.json').read_text());db=sqlite3.connect(args.output_dir/'scores.sqlite')
    results={m:{fid:json.loads(r) for fid,r in db.execute('SELECT code,result FROM scores WHERE method=?',(key,))} for m,key in model_meta['keys'].items()}
    summary=[]
    for project,record in projects.items():
        dest=args.output_dir/project;dest.mkdir(exist_ok=True);rows=[]
        for target in record['targets']:
            for method,cache in results.items():
                row=dict(target,method=method,score=None,raw_score=None,function_rank=None,function_percentile=None,slice_percentile=None)
                if target['status']=='ok':
                    result=cache.get(target['code_sha256'],dict(status='not_scored'));row['status']=result['status']
                    if result['status']=='scored':
                        local=target['line']-target['function_start']
                        if local not in result['lines']:row['status']='no_valid_tokens'
                        else:
                            j=result['lines'].index(local);v=np.array(result['scores']);s=v[j]
                            row.update(score=float(s),raw_score=result['raw_scores'][j],function_rank=1+int((v>s).sum()),
                                       function_percentile=float(((v<s).sum()+((v==s).sum()-1)/2)/(len(v)-1)) if len(v)>1 else .5)
                rows.append(row)
        groups=defaultdict(list)
        for r in rows:
            if r['status']=='scored':groups[r['method'],r['code_sha256']].append(r)
        for group in groups.values():
            # Unique slice source lines, not repeated DFG records, determine the percentile.
            unique={r['line']:r['score'] for r in group};v=np.array(list(unique.values()))
            for r in group:
                s=r['score'];r['slice_percentile']=float(((v<s).sum()+((v==s).sum()-1)/2)/(len(v)-1)) if len(v)>1 else .5
        fields=['requested_file','file','line','function','function_start','original_dfg_value','method','status','score','raw_score','function_rank','function_percentile','slice_percentile','code_sha256']
        write_csv(dest/'slice_scores.csv',rows,fields)
        write_csv(dest/'function_mapping.csv',record['functions'],['request','status','function'])
        for method in results:
            counts=Counter(r['status'] for r in rows if r['method']==method)
            summary.append(dict(project=project,method=method,source_status=record['status'],total_slice_lines=len(record['targets']),**counts))
    fields=['project','method','source_status','total_slice_lines']+sorted({k for r in summary for k in r}-{ 'project','method','source_status','total_slice_lines'})
    write_csv(args.output_dir/'summary.csv',summary,fields);db.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources',type=Path,default=ROOT.parents[1]/'temp/attention_sources/sources.json')
    parser.add_argument('--bench',type=Path,default=ROOT.parent/'bench')
    parser.add_argument('--output-dir',type=Path,default=ROOT/'outputs/bench_scores')
    parser.add_argument('--attention-run',type=Path,default=ROOT/'outputs/pipeline_20261011_231355/securebert2_classification')
    parser.add_argument('--rationale-run',type=Path,default=ROOT/'outputs/pipeline_20261012_231316/modernbert_rationale')
    parser.add_argument('--scope',choices=['slice','all'],default='slice',help='Scan all source files; score slice functions or all parsed functions')
    parser.add_argument('--stage',choices=['prepare','score','export','all'],default='all')
    parser.add_argument('--device',choices=['auto','cpu','cuda'],default='auto')
    parser.add_argument('--cpu-threads',type=int,default=4)
    parser.add_argument('--chunk-size',type=int,default=128)
    parser.add_argument('--local-files-only',action='store_true')
    args=parser.parse_args()
    if args.cpu_threads<1 or args.chunk_size<1:parser.error('Thread and chunk counts must be positive')
    if args.stage in ('prepare','all'):projects,candidates=prepare(args)
    else:
        projects=json.loads((args.output_dir/'mapping.json').read_text())
        candidates={r['code_sha256']:r['code'] for r in map(json.loads,(args.output_dir/'functions.jsonl').read_text().splitlines())}
    if args.stage in ('score','all'):score(args,candidates)
    if args.stage in ('export','all'):export(args,projects)


if __name__=='__main__':main()

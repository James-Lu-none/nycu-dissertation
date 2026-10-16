"""Refresh partial CSV results while inference fills the cache; stop when complete."""
import argparse,json,sqlite3,sys,time
from pathlib import Path
from types import SimpleNamespace
root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root))
from score_bench import export
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output-dir',type=Path,default=root/'outputs/bench_scores')
args=parser.parse_args();out=args.output_dir
while True:
    meta=json.loads((out/'models.json').read_text())
    candidates={json.loads(line)['code_sha256'] for line in (out/'functions.jsonl').read_text().splitlines()}
    mapping=json.loads((out/'mapping.json').read_text())
    export(args,mapping)
    with sqlite3.connect(out/'scores.sqlite') as db:
        counts={method:len(candidates&{row[0] for row in db.execute('SELECT code FROM scores WHERE method=?',(key,))}) for method,key in meta['keys'].items()}
    done=all(n==len(candidates) for n in counts.values())
    (out/'progress.json').write_text(json.dumps(dict(total_unique_functions=len(candidates),completed=counts,complete=done),indent=2))
    print(counts,'complete=',done,flush=True)
    if done:break
    time.sleep(30)

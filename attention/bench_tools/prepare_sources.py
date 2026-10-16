"""Run reviewed bench download scripts in isolated, reusable source directories."""
import argparse,concurrent.futures,hashlib,json,subprocess
from pathlib import Path
base=Path(__file__).resolve().parents[3]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bench',type=Path,default=base/'nycu-dissertation/bench')
parser.add_argument('--output-dir',type=Path,default=base/'temp/attention_sources')
args=parser.parse_args();bench=args.bench;out=args.output_dir;out.mkdir(parents=True,exist_ok=True)
groups={}
for p in sorted(bench.glob('*/download.sh')):
 script=p.read_text();h=hashlib.sha256(script.encode()).hexdigest()[:12];g=groups.setdefault(h,dict(script=script,projects=[]));g['projects'].append(p.parent.name)
def work(item):
 h,g=item;d=out/h;d.mkdir(exist_ok=True);mark=d/'ready.json'
 if mark.exists():return json.loads(mark.read_text())
 script=g['script'].replace('http://ftp.gnu.org/','https://ftp.gnu.org/')
 (d/'download.sh').write_text(script)
 print('Downloading',g['projects'][0],flush=True)
 with (d/'download.log').open('w') as log:
  try:r=subprocess.run(['bash','download.sh'],cwd=d,stdout=log,stderr=subprocess.STDOUT,timeout=600)
  except subprocess.TimeoutExpired:r=None
 roots=[p for p in d.iterdir() if p.is_dir()]
 result=dict(key=h,projects=g['projects'],directory=str(d),roots=[str(p) for p in roots],status='ready' if r is not None and r.returncode==0 and len(roots)==1 else 'failed',script_sha256=hashlib.sha256(g['script'].encode()).hexdigest())
 if result['status']=='ready':mark.write_text(json.dumps(result,indent=2))
 print(result['status'],g['projects'][0],flush=True);return result
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
 results=list(pool.map(work,groups.items()))
(out/'sources.json').write_text(json.dumps(results,indent=2))
print('Done',len(results),flush=True)

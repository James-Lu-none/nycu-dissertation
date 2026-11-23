import os
import re
import sys
import shutil
import tempfile
import subprocess
import concurrent.futures
import json
import yaml
from pathlib import Path
from collections import Counter
import pandas as pd

from target_graph.pipelines.label_audit import (
    parse_sanitizer_output,
    validate_graph_bundle,
    trace_to_basic_blocks,
    partition_target_candidates,
)
from target_graph.llvm.mapping import BasicBlockMapper

cases_yaml = Path('configs/projects/cases.yaml')
existing_cases = yaml.safe_load(cases_yaml.read_text())['cases']
existing_pocs = {os.path.abspath(c['poc_path']) for c in existing_cases}
existing_ids = {c['case_id'] for c in existing_cases}
print(f"Existing cases: {len(existing_cases)}")

# Load all candidate pools
f1 = json.load(open('scratch/fresh_crashes_pool.json'))
f2 = json.load(open('scratch/discovered_crashes.json'))
f3 = json.load(open('scratch/verified_candidates.json'))

combined = {}
for item in f1 + f2 + f3:
    poc = os.path.abspath(item.get('poc') or item.get('poc_path'))
    if poc in existing_pocs:
        continue
    tpl = item.get('template') or item.get('template_case_id')
    if not tpl or not (Path('cases') / tpl).exists():
        continue
    key = (tpl, poc)
    if key not in combined:
        combined[key] = item

print(f"Total candidate pairs to check: {len(combined)}")

# Template command rules
def get_target_cmd(tpl, poc, out_tmp):
    if 'cxxfilt' in tpl:
        return [], True  # stdin
    elif 'strip' in tpl:
        return ['-s', poc, '-o', out_tmp], False
    elif 'objcopy' in tpl:
        return ['--compress-debug-sections', poc, out_tmp], False
    elif 'objdump' in tpl:
        return ['-d', poc], False
    elif 'readelf' in tpl:
        return ['-w', poc], False
    elif 'nm' in tpl:
        return ['-A', '-a', '-l', '-S', '-s', '--special-syms', '--synthetic', '--with-symbol-versions', '-D', poc], False
    elif 'tiffcrop' in tpl:
        return ['-i', poc, out_tmp], False
    elif 'tiffcp' in tpl:
        return ['-i', poc, out_tmp], False
    elif 'tiffsplit' in tpl:
        return [poc], False
    elif 'imginfo' in tpl:
        return ['-f', poc], False
    elif 'mp42aac' in tpl:
        return [poc, out_tmp], False
    elif 'unzzipcat-mem' in tpl:
        return [poc], False
    elif 'swftophp' in tpl:
        return [poc], False
    elif 'imagew' in tpl:
        return [poc, out_tmp, '-outfmt', 'bmp'], False
    elif 'xmllint' in tpl:
        return ['--valid', '--noout', poc], False
    elif 'cjpeg' in tpl:
        return [poc], False
    elif 'jhead' in tpl:
        return ['-ds2020:01:01:1111111111111111111111111111111111111111', poc], False
    elif 'lrzip' in tpl:
        return ['-t', poc], False
    elif 'lame' in tpl:
        return [poc, '/dev/null'], False
    else:
        return [poc], False

# Preload template mappers, parquet edges, and inst binaries
template_cache = {}
for tpl, item in list(combined.items()):
    tpl_name = tpl[0]
    if tpl_name not in template_cache:
        tpl_dir = Path('cases') / tpl_name
        bb_map_file = tpl_dir / 'bb_map.jsonl'
        parquet_dir = tpl_dir / 'parquet'
        inst_bin = list(tpl_dir.glob('*_inst'))
        if bb_map_file.exists() and parquet_dir.exists() and inst_bin:
            template_cache[tpl_name] = {
                'mapper': BasicBlockMapper(bb_map_file),
                'edges_df': pd.read_parquet(parquet_dir / 'edges.parquet'),
                'nodes_df': pd.read_parquet(parquet_dir / 'nodes.parquet'),
                'inst_bin': str(inst_bin[0]),
                'tpl_dir': str(tpl_dir),
            }

print(f"Preloaded cache for {len(template_cache)} templates.")

env_base = os.environ.copy()
env_base['ASAN_SYMBOLIZER_PATH'] = '/usr/bin/llvm-symbolizer-18'
env_base['ASAN_OPTIONS'] = 'abort_on_error=0:symbolize=1:external_symbolizer_path=/usr/bin/llvm-symbolizer-18:strip_path_prefix=/workspace/:handle_segv=1'

def verify_single_candidate(tpl_name, poc):
    if tpl_name not in template_cache:
        return None
    cache = template_cache[tpl_name]
    inst_bin = cache['inst_bin']
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        trace_file = tmp_path / 'trace_crash.txt'
        out_file = tmp_path / 'out.tmp'
        env = env_base.copy()
        env['TARGET_GRAPH_TRACE_FILE'] = str(trace_file)
        
        args, is_stdin = get_target_cmd(tpl_name, poc, str(out_file))
        
        try:
            if is_stdin:
                with open(poc, 'rb') as f:
                    r = subprocess.run([inst_bin] + args, stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env, timeout=2.5)
            else:
                r = subprocess.run([inst_bin] + args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env, timeout=2.5)
        except Exception:
            return None
        
        stderr_text = r.stderr.decode('utf-8', errors='replace')
        if not trace_file.exists() or trace_file.stat().st_size == 0:
            return None
        
        san_report = parse_sanitizer_output(stderr_text)
        if not san_report or 'leak' in san_report.error_type.lower() or san_report.error_type.isdigit():
            return None
        
        # Filter stack frames for application code
        target_frame = None
        for f in san_report.frames:
            fn = f.function_name.lower()
            if any(p in fn for p in ['__asan', '__interceptor', 'strlen', 'memcpy', 'memset', 'malloc', 'free', 'realloc']):
                continue
            if f.line_number > 0 and f.source_file and f.function_name != 'unknown':
                target_frame = f
                break
        
        if not target_frame:
            return None
        
        mapper = cache['mapper']
        obs_file = target_frame.source_file
        obs_line = target_frame.line_number
        obs_fn = target_frame.function_name
        obs_file_base = Path(obs_file).name
        
        target_bbs = mapper.map_source_location(obs_file, obs_line, function_name=obs_fn)
        if not target_bbs:
            target_bbs = mapper.map_source_location(obs_file_base, obs_line, function_name=obs_fn)
        if not target_bbs:
            target_bbs = mapper.map_source_location(obs_file_base, obs_line)
        if not target_bbs:
            return None
        
        # Check executed bbs in trace
        try:
            executed_bbs = trace_to_basic_blocks(trace_file, Path(inst_bin), mapper)
        except Exception:
            return None
        
        in_trace_bbs = [b for b in target_bbs if b in executed_bbs]
        if not in_trace_bbs:
            for delta in [-1, 1, -2, 2, -3, 3, -4, 4]:
                alt_bbs = mapper.map_source_location(obs_file, obs_line + delta, function_name=obs_fn)
                alt_in_trace = [b for b in alt_bbs if b in executed_bbs]
                if alt_in_trace:
                    target_bbs = alt_bbs
                    in_trace_bbs = alt_in_trace
                    break
        
        if not in_trace_bbs:
            return None
        
        target_bb = in_trace_bbs[0]
        
        # Partition
        all_bbs = set(cache['nodes_df']['bb_id'].unique())
        partition = partition_target_candidates(
            all_bbs=all_bbs,
            executed_trace_bbs=executed_bbs,
            edges_df=cache['edges_df'],
            target_bb=target_bb,
        )
        
        if target_bb not in partition.E_t or len(partition.P_t) == 0:
            return None
        
        return {
            'template': tpl_name,
            'poc': poc,
            'sanitizer': san_report.error_type,
            'function': obs_fn,
            'file': obs_file_base,
            'line': obs_line,
            'target_bb': target_bb,
            'num_executed_Et': len(partition.E_t),
            'positive_yield': len(partition.P_t),
            'stderr_text': stderr_text,
        }

tasks = list(combined.keys())
print(f"Starting parallel validation of {len(tasks)} tasks...")

passed_candidates = []
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
    futures = {executor.submit(verify_single_candidate, tpl, poc): (tpl, poc) for tpl, poc in tasks}
    for fut in concurrent.futures.as_completed(futures):
        res = fut.result()
        if res:
            passed_candidates.append(res)
            if len(passed_candidates) % 20 == 0:
                print(f"Progress: {len(passed_candidates)} verified passed!")

print(f"\nTOTAL VERIFIED PASSED CANDIDATES: {len(passed_candidates)}")
with open('scratch/fully_verified_candidates.json', 'w') as f:
    json.dump(passed_candidates, f, indent=2)

counts = Counter(c['template'] for c in passed_candidates)
print("\nDistribution across templates:")
for tpl, cnt in counts.most_common():
    print(f"  {tpl}: {cnt}")

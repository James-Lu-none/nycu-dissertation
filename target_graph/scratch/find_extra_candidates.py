import os
import re
import sys
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
    trace_to_basic_blocks,
    partition_target_candidates,
)
from target_graph.llvm.mapping import BasicBlockMapper

cases_yaml = Path('configs/projects/cases.yaml')
existing_cases = yaml.safe_load(cases_yaml.read_text())['cases']
existing_pocs = {os.path.abspath(c['poc_path']) for c in existing_cases}

# Load already verified candidates
f1 = json.load(open('scratch/fully_verified_candidates.json'))
f2 = json.load(open('scratch/broad_scan_results.json'))

already_verified = {}
for item in f1 + f2:
    poc = os.path.abspath(item['poc'])
    if poc in existing_pocs:
        continue
    tpl = item['template']
    key = (tpl, poc)
    if key not in already_verified:
        already_verified[key] = item

print(f"Already have {len(already_verified)} verified candidates.")

# Additional test pairs to probe
extra_tasks = []

# 1. Jasper 35 pocs
jasper_pocs = list(Path('build_test/asarubbo_poc').glob('*jasper*'))
for p in jasper_pocs:
    ap = str(p.resolve())
    if ap not in existing_pocs and ('jasper-1.900.1_imginfo_CVE-2017-6850', ap) not in already_verified:
        extra_tasks.append({
            'template': 'jasper-1.900.1_imginfo_CVE-2017-6850',
            'poc': ap,
            'cmd': lambda p, o: ['-f', p],
            'stdin': False,
            'timeout': 6.0
        })

# 2. Libtiff 48 pocs on tiffcrop with different args or on tiffcp
tiff_pocs = list(Path('build_test/asarubbo_poc').glob('*libtiff*'))
for p in tiff_pocs:
    ap = str(p.resolve())
    if ap not in existing_pocs and ('libtiff-4.0.6_tiffcrop_CVE-2016-10272', ap) not in already_verified:
        extra_tasks.append({
            'template': 'libtiff-4.0.6_tiffcrop_CVE-2016-10272',
            'poc': ap,
            'cmd': lambda p, o: ['-i', p, o],
            'stdin': False,
            'timeout': 3.0
        })
    if ap not in existing_pocs and ('libtiff-4.0.6_tiffcp_CVE-2016-10269', ap) not in already_verified:
        extra_tasks.append({
            'template': 'libtiff-4.0.6_tiffcp_CVE-2016-10269',
            'poc': ap,
            'cmd': lambda p, o: ['-i', p, o],
            'stdin': False,
            'timeout': 3.0
        })

# 3. Libming benchmark pocs
ming_pocs = list(Path('../bench/target/benchmark-project').glob('libming*/poc*/*'))
for p in ming_pocs:
    if p.is_file():
        ap = str(p.resolve())
        if ap not in existing_pocs and ('libming-4.8_swftophp_CVE-2018-7868', ap) not in already_verified:
            extra_tasks.append({
                'template': 'libming-4.8_swftophp_CVE-2018-7868',
                'poc': ap,
                'cmd': lambda p, o: [p],
                'stdin': False,
                'timeout': 3.0
            })
        if ap not in existing_pocs and ('libming-4.7.1_swftophp_CVE-2017-7578', ap) not in already_verified:
            extra_tasks.append({
                'template': 'libming-4.7.1_swftophp_CVE-2017-7578',
                'poc': ap,
                'cmd': lambda p, o: [p],
                'stdin': False,
                'timeout': 3.0
            })

# 4. Binutils benchmark pocs
bin_pocs = list(Path('../bench/target/benchmark-project').glob('binutils*/poc*/*'))
for p in bin_pocs:
    if p.is_file():
        ap = str(p.resolve())
        if ap not in existing_pocs:
            if '2.26' in str(p) and ('binutils-2.26_cxxfilt_CVE-2016-4487', ap) not in already_verified:
                extra_tasks.append({
                    'template': 'binutils-2.26_cxxfilt_CVE-2016-4487',
                    'poc': ap,
                    'cmd': lambda p, o: [],
                    'stdin': True,
                    'timeout': 3.0
                })
            if '2.27' in str(p) and ('binutils-2.27_strip_CVE-2017-7303', ap) not in already_verified:
                extra_tasks.append({
                    'template': 'binutils-2.27_strip_CVE-2017-7303',
                    'poc': ap,
                    'cmd': lambda p, o: ['-s', p, '-o', o],
                    'stdin': False,
                    'timeout': 3.0
                })
            if '2.28' in str(p) and ('binutils-2.28_objdump_CVE-2017-8392', ap) not in already_verified:
                extra_tasks.append({
                    'template': 'binutils-2.28_objdump_CVE-2017-8392',
                    'poc': ap,
                    'cmd': lambda p, o: ['-d', p],
                    'stdin': False,
                    'timeout': 3.0
                })
                extra_tasks.append({
                    'template': 'binutils-2.28_objcopy_CVE-2017-8393',
                    'poc': ap,
                    'cmd': lambda p, o: ['--compress-debug-sections', p, o],
                    'stdin': False,
                    'timeout': 3.0
                })
            if '2.29' in str(p) and ('binutils-2.29_nm_CVE-2017-15938', ap) not in already_verified:
                extra_tasks.append({
                    'template': 'binutils-2.29_nm_CVE-2017-15938',
                    'poc': ap,
                    'cmd': lambda p, o: ['-l', p],
                    'stdin': False,
                    'timeout': 3.0
                })
            if '2.29' in str(p) and ('binutils-2.29_readelf_CVE-2017-16828', ap) not in already_verified:
                extra_tasks.append({
                    'template': 'binutils-2.29_readelf_CVE-2017-16828',
                    'poc': ap,
                    'cmd': lambda p, o: ['-w', p],
                    'stdin': False,
                    'timeout': 3.0
                })

# 5. Linuxflaw matching pocs
linuxflaw_dirs = list(Path('build_test/linuxflaw_poc').glob('*'))
for d in linuxflaw_dirs:
    if d.is_dir():
        rm = d / 'README.md'
        if rm.exists():
            content = rm.read_text(errors='ignore')
            pocs_in_d = [f for f in d.glob('*') if f.name != 'README.md' and not f.name.endswith(('.php', '.py', '.sh', '.patch', '.zip'))]
            if pocs_in_d:
                p = pocs_in_d[0]
                ap = str(p.resolve())
                if ap in existing_pocs:
                    continue
                if 'bento4' in content.lower() and ('bento4-1.5.0_mp42aac_CVE-2017-14638', ap) not in already_verified:
                    extra_tasks.append({
                        'template': 'bento4-1.5.0_mp42aac_CVE-2017-14638',
                        'poc': ap,
                        'cmd': lambda p, o: [p, o],
                        'stdin': False,
                        'timeout': 3.0
                    })
                if 'zziplib' in content.lower() and ('zziplib-0.13.62_unzzipcat-mem_CVE-2017-5974', ap) not in already_verified:
                    extra_tasks.append({
                        'template': 'zziplib-0.13.62_unzzipcat-mem_CVE-2017-5974',
                        'poc': ap,
                        'cmd': lambda p, o: [p],
                        'stdin': False,
                        'timeout': 3.0
                    })
                if 'imageworsener' in content.lower() and ('imageworsener-1.3.1_imagew_CVE-2017-9204', ap) not in already_verified:
                    extra_tasks.append({
                        'template': 'imageworsener-1.3.1_imagew_CVE-2017-9204',
                        'poc': ap,
                        'cmd': lambda p, o: [p, o, '-outfmt', 'bmp'],
                        'stdin': False,
                        'timeout': 3.0
                    })

print(f"Total extra tasks prepared: {len(extra_tasks)}")

# Preload cache
templates_needed = {t['template'] for t in extra_tasks}
template_cache = {}
for tpl_name in templates_needed:
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
        }

env_base = os.environ.copy()
env_base['ASAN_SYMBOLIZER_PATH'] = '/usr/bin/llvm-symbolizer-18'
env_base['ASAN_OPTIONS'] = 'abort_on_error=0:symbolize=1:external_symbolizer_path=/usr/bin/llvm-symbolizer-18:strip_path_prefix=/workspace/:handle_segv=1'

def run_extra(task):
    tpl_name = task['template']
    poc = task['poc']
    cache = template_cache.get(tpl_name)
    if not cache:
        return None
    inst_bin = cache['inst_bin']
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        trace_file = tmp_path / 'trace_crash.txt'
        out_file = tmp_path / 'out.tmp'
        env = env_base.copy()
        env['TARGET_GRAPH_TRACE_FILE'] = str(trace_file)
        
        args = task['cmd'](poc, str(out_file))
        is_stdin = task['stdin']
        
        try:
            if is_stdin:
                with open(poc, 'rb') as f:
                    r = subprocess.run([inst_bin] + args, stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env, timeout=task['timeout'])
            else:
                r = subprocess.run([inst_bin] + args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env, timeout=task['timeout'])
        except Exception:
            return None
        
        stderr_text = r.stderr.decode('utf-8', errors='replace')
        if not trace_file.exists() or trace_file.stat().st_size == 0:
            return None
        
        san_report = parse_sanitizer_output(stderr_text)
        if not san_report or 'leak' in san_report.error_type.lower() or san_report.error_type.isdigit():
            return None
        
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
        }

extra_results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
    futures = [executor.submit(run_extra, t) for t in extra_tasks]
    for fut in concurrent.futures.as_completed(futures):
        res = fut.result()
        if res:
            extra_results.append(res)
            print(f"Extra candidate found! Total: {len(extra_results)} ({res['template']})")

print(f"\nEXTRA CANDIDATES VERIFIED: {len(extra_results)}")
with open('scratch/extra_candidates.json', 'w') as f:
    json.dump(extra_results, f, indent=2)

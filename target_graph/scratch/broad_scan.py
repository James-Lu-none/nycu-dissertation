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
    trace_to_basic_blocks,
    partition_target_candidates,
)
from target_graph.llvm.mapping import BasicBlockMapper

cases_yaml = Path('configs/projects/cases.yaml')
existing_cases = yaml.safe_load(cases_yaml.read_text())['cases']
existing_pocs = {os.path.abspath(c['poc_path']) for c in existing_cases}
print(f"Existing cases: {len(existing_cases)}")

# Collect all PoCs
pocs = []
for d in ['build_test/asarubbo_poc', 'build_test/linuxflaw_poc', '../bench/target/benchmark-project']:
    p = Path(d)
    if p.exists():
        for f in p.rglob('*'):
            if f.is_file() and not f.name.endswith(('.o', '.a', '.so', '.py', '.sh', '.md', '.git', '.pyc')):
                ap = os.path.abspath(str(f))
                if ap not in existing_pocs:
                    pocs.append(ap)

pocs = sorted(list(set(pocs)))
print(f"Total non-existing candidate PoCs: {len(pocs)}")

# Define target configurations
targets_config = [
    # ELF / Binutils
    {
        'key': 'binutils-2.28_objdump_d',
        'template': 'binutils-2.28_objdump_CVE-2017-8392',
        'cmd': lambda p, o: ['-d', p],
        'stdin': False,
        'types': ['ELF', 'OTHER']
    },
    {
        'key': 'binutils-2.28_objdump_W',
        'template': 'binutils-2.28_objdump_CVE-2017-8392',
        'cmd': lambda p, o: ['-W', p],
        'stdin': False,
        'types': ['ELF', 'OTHER']
    },
    {
        'key': 'binutils-2.28_objdump_SD',
        'template': 'binutils-2.28_objdump_CVE-2017-8392',
        'cmd': lambda p, o: ['-SD', p],
        'stdin': False,
        'types': ['ELF', 'OTHER']
    },
    {
        'key': 'binutils-2.28_objcopy_comp',
        'template': 'binutils-2.28_objcopy_CVE-2017-8393',
        'cmd': lambda p, o: ['--compress-debug-sections', p, o],
        'stdin': False,
        'types': ['ELF', 'OTHER']
    },
    {
        'key': 'binutils-2.28_objcopy_Gs',
        'template': 'binutils-2.28_objcopy_CVE-2017-8393',
        'cmd': lambda p, o: ['-Gs', p, o],
        'stdin': False,
        'types': ['ELF', 'OTHER']
    },
    {
        'key': 'binutils-2.27_strip',
        'template': 'binutils-2.27_strip_CVE-2017-7303',
        'cmd': lambda p, o: ['-s', p, '-o', o],
        'stdin': False,
        'types': ['ELF', 'OTHER']
    },
    {
        'key': 'binutils-2.29_readelf_w',
        'template': 'binutils-2.29_readelf_CVE-2017-16828',
        'cmd': lambda p, o: ['-w', p],
        'stdin': False,
        'types': ['ELF', 'OTHER']
    },
    {
        'key': 'binutils-2.29_readelf_a',
        'template': 'binutils-2.29_readelf_CVE-2017-16828',
        'cmd': lambda p, o: ['-a', p],
        'stdin': False,
        'types': ['ELF', 'OTHER']
    },
    {
        'key': 'binutils-2.29_nm_all',
        'template': 'binutils-2.29_nm_CVE-2017-15938',
        'cmd': lambda p, o: ['-A', '-a', '-l', '-S', '-s', '--special-syms', '--synthetic', '--with-symbol-versions', '-D', p],
        'stdin': False,
        'types': ['ELF', 'OTHER']
    },
    {
        'key': 'binutils-2.29_nm_l',
        'template': 'binutils-2.29_nm_CVE-2017-15938',
        'cmd': lambda p, o: ['-l', p],
        'stdin': False,
        'types': ['ELF', 'OTHER']
    },
    {
        'key': 'binutils-2.26_cxxfilt',
        'template': 'binutils-2.26_cxxfilt_CVE-2016-4487',
        'cmd': lambda p, o: [],
        'stdin': True,
        'types': ['OTHER']
    },
    # TIFF
    {
        'key': 'libtiff-4.0.6_tiffcrop',
        'template': 'libtiff-4.0.6_tiffcrop_CVE-2016-10272',
        'cmd': lambda p, o: ['-i', p, o],
        'stdin': False,
        'types': ['TIFF', 'OTHER']
    },
    {
        'key': 'libtiff-4.0.6_tiffcrop_E',
        'template': 'libtiff-4.0.6_tiffcrop_CVE-2016-10272',
        'cmd': lambda p, o: ['-E', 'top', '-i', p, o],
        'stdin': False,
        'types': ['TIFF', 'OTHER']
    },
    {
        'key': 'libtiff-4.0.6_tiffcp',
        'template': 'libtiff-4.0.6_tiffcp_CVE-2016-10269',
        'cmd': lambda p, o: ['-i', p, o],
        'stdin': False,
        'types': ['TIFF', 'OTHER']
    },
    # Jasper
    {
        'key': 'jasper-1.900.1_imginfo',
        'template': 'jasper-1.900.1_imginfo_CVE-2017-6850',
        'cmd': lambda p, o: ['-f', p],
        'stdin': False,
        'types': ['OTHER']
    },
    # Bento4
    {
        'key': 'bento4-1.5.0_mp42aac',
        'template': 'bento4-1.5.0_mp42aac_CVE-2017-14638',
        'cmd': lambda p, o: [p, o],
        'stdin': False,
        'types': ['MP4', 'OTHER']
    },
    # Zziplib
    {
        'key': 'zziplib-0.13.62_unzzipcat-mem',
        'template': 'zziplib-0.13.62_unzzipcat-mem_CVE-2017-5974',
        'cmd': lambda p, o: [p],
        'stdin': False,
        'types': ['ZIP', 'OTHER']
    },
    # Libming
    {
        'key': 'libming-4.7.1_swftophp',
        'template': 'libming-4.7.1_swftophp_CVE-2017-7578',
        'cmd': lambda p, o: [p],
        'stdin': False,
        'types': ['SWF', 'OTHER']
    },
    {
        'key': 'libming-4.8_swftophp',
        'template': 'libming-4.8_swftophp_CVE-2018-7868',
        'cmd': lambda p, o: [p],
        'stdin': False,
        'types': ['SWF', 'OTHER']
    },
    # Imageworsener
    {
        'key': 'imageworsener-1.3.1_imagew',
        'template': 'imageworsener-1.3.1_imagew_CVE-2017-9204',
        'cmd': lambda p, o: [p, o, '-outfmt', 'bmp'],
        'stdin': False,
        'types': ['BMP', 'OTHER']
    },
    # Libxml2
    {
        'key': 'libxml2-2.9.4_xmllint_valid',
        'template': 'libxml2-2.9.4_xmllint_CVE-2017-9047',
        'cmd': lambda p, o: ['--valid', '--noout', p],
        'stdin': False,
        'types': ['XML', 'OTHER']
    },
    {
        'key': 'libxml2-2.9.4_xmllint_rec',
        'template': 'libxml2-2.9.4_xmllint_CVE-2017-9047',
        'cmd': lambda p, o: ['--recover', '--postvalid', p],
        'stdin': False,
        'types': ['XML', 'OTHER']
    },
    # Jhead
    {
        'key': 'jhead-3.04_jhead',
        'template': 'jhead-3.04_jhead_issue54',
        'cmd': lambda p, o: ['-ds2020:01:01:1111111111111111111111111111111111111111', p],
        'stdin': False,
        'types': ['JPEG', 'OTHER']
    },
    {
        'key': 'jhead-3.04_jhead_te',
        'template': 'jhead-3.04_jhead_issue55',
        'cmd': lambda p, o: ['-te', 'A'*4096 + '&i' + 'B'*500, p],
        'stdin': False,
        'types': ['JPEG', 'OTHER']
    },
    # Lrzip
    {
        'key': 'lrzip-ed51e14_lrzip',
        'template': 'lrzip-ed51e14_lrzip_CVE-2018-11496',
        'cmd': lambda p, o: ['-t', p],
        'stdin': False,
        'types': ['OTHER']
    },
    # Lame
    {
        'key': 'lame-3.99.5_lame',
        'template': 'lame-3.99.5_lame_CVE-2015-9101',
        'cmd': lambda p, o: [p, '/dev/null'],
        'stdin': False,
        'types': ['AUDIO', 'OTHER']
    },
]

# Preload template cache
template_cache = {}
for t in targets_config:
    tpl_name = t['template']
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
            }

print(f"Preloaded cache for {len(template_cache)} templates.")

# Pre-classify PoCs
poc_types = {}
for p in pocs:
    try:
        with open(p, 'rb') as f:
            h = f.read(16)
            if h.startswith(b'\x7fELF'):
                poc_types[p] = 'ELF'
            elif h.startswith(b'II*\x00') or h.startswith(b'MM\x00*'):
                poc_types[p] = 'TIFF'
            elif h.startswith(b'\xff\xd8\xff'):
                poc_types[p] = 'JPEG'
            elif h.startswith(b'FWS') or h.startswith(b'CWS') or h.startswith(b'ZWS'):
                poc_types[p] = 'SWF'
            elif h.startswith(b'PK\x03\x04'):
                poc_types[p] = 'ZIP'
            elif b'ftyp' in h[:12]:
                poc_types[p] = 'MP4'
            elif h.startswith(b'<?xml') or h.startswith(b'<!DOCTYPE') or h.startswith(b'<'):
                poc_types[p] = 'XML'
            elif h.startswith(b'BM'):
                poc_types[p] = 'BMP'
            elif h.startswith(b'ID3') or h.startswith(b'\xff\xfb') or h.startswith(b'RIFF'):
                poc_types[p] = 'AUDIO'
            else:
                poc_types[p] = 'OTHER'
    except Exception:
        poc_types[p] = 'OTHER'

# Build test tasks: if poc matches target's types OR poc has target keywords in path
tasks = []
for t in targets_config:
    tpl_name = t['template']
    if tpl_name not in template_cache:
        continue
    # determine keywords from key
    kw = t['key'].split('-')[0].split('_')[0].lower()
    for p in pocs:
        ptype = poc_types.get(p, 'OTHER')
        kw_match = kw in p.lower()
        type_match = ptype in t['types']
        if kw_match or (type_match and ptype != 'OTHER'):
            tasks.append((t, p))

print(f"Total targeted test tasks: {len(tasks)}")

env_base = os.environ.copy()
env_base['ASAN_SYMBOLIZER_PATH'] = '/usr/bin/llvm-symbolizer-18'
env_base['ASAN_OPTIONS'] = 'abort_on_error=0:symbolize=1:external_symbolizer_path=/usr/bin/llvm-symbolizer-18:strip_path_prefix=/workspace/:handle_segv=1'

def run_task(target_cfg, poc):
    tpl_name = target_cfg['template']
    cache = template_cache[tpl_name]
    inst_bin = cache['inst_bin']
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        trace_file = tmp_path / 'trace_crash.txt'
        out_file = tmp_path / 'out.tmp'
        env = env_base.copy()
        env['TARGET_GRAPH_TRACE_FILE'] = str(trace_file)
        
        args = target_cfg['cmd'](poc, str(out_file))
        is_stdin = target_cfg['stdin']
        
        try:
            if is_stdin:
                with open(poc, 'rb') as f:
                    r = subprocess.run([inst_bin] + args, stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env, timeout=3.0)
            else:
                r = subprocess.run([inst_bin] + args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env, timeout=3.0)
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
            'target_key': target_cfg['key'],
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

print("Running broad scan in parallel...")
broad_results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
    futures = {executor.submit(run_task, t, p): (t['key'], p) for t, p in tasks}
    for fut in concurrent.futures.as_completed(futures):
        res = fut.result()
        if res:
            broad_results.append(res)
            if len(broad_results) % 25 == 0:
                print(f"Broad scan progress: {len(broad_results)} passed!")

print(f"\nBROAD SCAN COMPLETED: {len(broad_results)} valid passed!")
with open('scratch/broad_scan_results.json', 'w') as f:
    json.dump(broad_results, f, indent=2)

counts = Counter(r['target_key'] for r in broad_results)
for k, v in counts.most_common():
    print(f"  {k}: {v}")

EOF

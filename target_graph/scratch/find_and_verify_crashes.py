import os
import re
import subprocess
import concurrent.futures
import json
import yaml
from pathlib import Path
from target_graph.pipelines.label_audit import parse_sanitizer_output
from target_graph.llvm.mapping import BasicBlockMapper

cases_yaml = Path('configs/projects/cases.yaml')
existing_cases = yaml.safe_load(cases_yaml.read_text())['cases']
existing_pocs = {os.path.abspath(c['poc_path']) for c in existing_cases}
existing_ids = {c['case_id'] for c in existing_cases}
print(f"Existing cases: {len(existing_cases)}")

# Load templates
targets = [
    {
        'key': 'libtiff-4.0.6_tiffcrop',
        'template': 'libtiff-4.0.6_tiffcrop_CVE-2016-10272',
        'cmd': lambda p: ['-i', str(p), '/tmp/out.tif'],
        'stdin': False,
        'kw': ['tiff', 'libtiff']
    },
    {
        'key': 'libtiff-4.0.6_tiffcp',
        'template': 'libtiff-4.0.6_tiffcp_CVE-2016-10269',
        'cmd': lambda p: ['-i', str(p), '/tmp/out.tif'],
        'stdin': False,
        'kw': ['tiff', 'libtiff']
    },
    {
        'key': 'libtiff-4.0.6_tiffsplit',
        'template': 'libtiff-4.0.6_tiffsplit_CVE-2016-10095',
        'cmd': lambda p: [str(p)],
        'stdin': False,
        'kw': ['tiff', 'libtiff']
    },
    {
        'key': 'jasper-1.900.1_imginfo',
        'template': 'jasper-1.900.1_imginfo_CVE-2017-6850',
        'cmd': lambda p: ['-f', str(p)],
        'stdin': False,
        'kw': ['jasper', 'imginfo', 'jpc', 'jp2']
    },
    {
        'key': 'bento4-1.5.0_mp42aac',
        'template': 'bento4-1.5.0_mp42aac_CVE-2017-14638',
        'cmd': lambda p: [str(p), '/tmp/out.aac'],
        'stdin': False,
        'kw': ['bento4', 'mp42aac', 'mp4']
    },
    {
        'key': 'zziplib-0.13.62_unzzipcat-mem',
        'template': 'zziplib-0.13.62_unzzipcat-mem_CVE-2017-5974',
        'cmd': lambda p: [str(p)],
        'stdin': False,
        'kw': ['zziplib', 'zzip', 'zip']
    },
    {
        'key': 'libming-4.7.1_swftophp',
        'template': 'libming-4.7.1_swftophp_CVE-2017-7578',
        'cmd': lambda p: [str(p)],
        'stdin': False,
        'kw': ['libming', 'ming', 'swf', 'swftophp']
    },
    {
        'key': 'libming-4.8_swftophp',
        'template': 'libming-4.8_swftophp_CVE-2018-7868',
        'cmd': lambda p: [str(p)],
        'stdin': False,
        'kw': ['libming', 'ming', 'swf', 'swftophp']
    },
    {
        'key': 'imageworsener-1.3.1_imagew',
        'template': 'imageworsener-1.3.1_imagew_CVE-2017-9204',
        'cmd': lambda p: [str(p), '/tmp/out.bmp', '-outfmt', 'bmp'],
        'stdin': False,
        'kw': ['imageworsener', 'imagew', 'image']
    },
    {
        'key': 'binutils-2.26_cxxfilt',
        'template': 'binutils-2.26_cxxfilt_CVE-2016-4487',
        'cmd': lambda p: [],
        'stdin': True,
        'kw': ['binutils', 'cxxfilt', 'cplus', 'demangle']
    },
    {
        'key': 'binutils-2.27_strip',
        'template': 'binutils-2.27_strip_CVE-2017-7303',
        'cmd': lambda p: ['-s', str(p), '-o', '/tmp/out_strip'],
        'stdin': False,
        'kw': ['binutils', 'strip', 'elf', 'bfd']
    },
    {
        'key': 'binutils-2.28_objcopy',
        'template': 'binutils-2.28_objcopy_CVE-2017-8393',
        'cmd': lambda p: ['--compress-debug-sections', str(p), '/tmp/out_objcopy'],
        'stdin': False,
        'kw': ['binutils', 'objcopy', 'bfd', 'elf']
    },
    {
        'key': 'binutils-2.28_objdump',
        'template': 'binutils-2.28_objdump_CVE-2017-8392',
        'cmd': lambda p: ['-d', str(p)],
        'stdin': False,
        'kw': ['binutils', 'objdump', 'bfd', 'dwarf']
    },
    {
        'key': 'binutils-2.29_nm',
        'template': 'binutils-2.29_nm_CVE-2017-15938',
        'cmd': lambda p: ['-A', '-a', '-l', '-S', '-s', '--special-syms', '--synthetic', '--with-symbol-versions', '-D', str(p)],
        'stdin': False,
        'kw': ['binutils', 'nm', 'dwarf', 'bfd']
    },
    {
        'key': 'binutils-2.29_readelf',
        'template': 'binutils-2.29_readelf_CVE-2017-16828',
        'cmd': lambda p: ['-w', str(p)],
        'stdin': False,
        'kw': ['binutils', 'readelf', 'dwarf', 'elf']
    },
    {
        'key': 'libxml2-2.9.4_xmllint',
        'template': 'libxml2-2.9.4_xmllint_CVE-2017-9047',
        'cmd': lambda p: ['--valid', '--noout', str(p)],
        'stdin': False,
        'kw': ['libxml2', 'xml', 'xmllint']
    },
    {
        'key': 'libjpeg-1.5.90_cjpeg',
        'template': 'libjpeg-1.5.90_cjpeg_CVE-2018-14498',
        'cmd': lambda p: [str(p)],
        'stdin': False,
        'kw': ['libjpeg', 'jpeg', 'cjpeg']
    },
    {
        'key': 'lrzip-ed51e14_lrzip',
        'template': 'lrzip-ed51e14_lrzip_CVE-2018-11496',
        'cmd': lambda p: ['-t', str(p)],
        'stdin': False,
        'kw': ['lrzip', 'lrz']
    },
    {
        'key': 'lame-3.99.5_lame',
        'template': 'lame-3.99.5_lame_CVE-2015-9101',
        'cmd': lambda p: [str(p), '/dev/null'],
        'stdin': False,
        'kw': ['lame', 'mp3', 'wav']
    }
]

# Pre-load basic block mappers for each template
mappers = {}
for t in targets:
    tpl_dir = Path('cases') / t['template']
    bb_map_file = tpl_dir / 'bb_map.jsonl'
    if bb_map_file.exists():
        mappers[t['key']] = BasicBlockMapper(bb_map_file)
        # also find inst binary
        insts = list(tpl_dir.glob('*_inst'))
        if insts:
            t['inst_bin'] = str(insts[0])
            print(f"Loaded {t['key']}: {t['inst_bin']}")

all_pocs = []
for src in ['build_test/asarubbo_poc', 'build_test/linuxflaw_poc', '../bench/target/benchmark-project']:
    p = Path(src)
    if p.exists():
        for f in p.rglob('*'):
            if f.is_file() and not f.name.endswith(('.o', '.a', '.so', '.py', '.sh', '.md', '.git', '.pyc')):
                all_pocs.append(str(f.resolve()))

print(f"Total PoC files: {len(all_pocs)}")

env = os.environ.copy()
env['ASAN_SYMBOLIZER_PATH'] = '/usr/bin/llvm-symbolizer-18'
env['ASAN_OPTIONS'] = 'abort_on_error=0:symbolize=1:external_symbolizer_path=/usr/bin/llvm-symbolizer-18:strip_path_prefix=/workspace/:handle_segv=1'

def test_target_poc(tgt, poc):
    if str(Path(poc).resolve()) in existing_pocs:
        return None
    inst_bin = tgt.get('inst_bin')
    if not inst_bin or not os.path.exists(inst_bin):
        return None
    try:
        if tgt['stdin']:
            with open(poc, 'rb') as f:
                r = subprocess.run([inst_bin] + tgt['cmd'](poc), stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env, timeout=1.5)
        else:
            r = subprocess.run([inst_bin] + tgt['cmd'](poc), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env, timeout=1.5)
        
        stderr_text = r.stderr.decode('utf-8', errors='replace')
        if 'ERROR: AddressSanitizer:' not in stderr_text and 'SUMMARY: AddressSanitizer:' not in stderr_text:
            return None
        
        san_report = parse_sanitizer_output(stderr_text)
        if not san_report or san_report.error_type.lower() == 'leak':
            return None
        
        # Find crash frame
        target_frame = None
        for f in san_report.frames:
            fn = f.function_name.lower()
            if fn in ['__asan_memcpy', '__asan_memset', '__interceptor_malloc', 'strlen', 'memcpy', 'memset', 'free', 'malloc']:
                continue
            if f.line_number > 0 and f.source_file and f.function_name != 'unknown':
                target_frame = f
                break
        
        if not target_frame:
            return None
        
        # Check mapping to BB
        mapper = mappers[tgt['key']]
        obs_file = target_frame.source_file
        obs_line = target_frame.line_number
        obs_fn = target_frame.function_name
        bbs = mapper.map_source_location(obs_file, obs_line, function_name=obs_fn)
        if not bbs:
            bbs = mapper.map_source_location(os.path.basename(obs_file), obs_line)
        if not bbs:
            return None
        
        return {
            'target_key': tgt['key'],
            'template': tgt['template'],
            'poc': poc,
            'sanitizer': san_report.error_type,
            'function': obs_fn,
            'file': os.path.basename(obs_file),
            'line': obs_line,
            'target_bbs': bbs,
        }
    except Exception:
        return None

tasks = []
for t in targets:
    if t['key'] not in mappers:
        continue
    matched = [p for p in all_pocs if any(k.lower() in p.lower() for k in t['kw'])]
    for p in matched:
        tasks.append((t, p))

print(f"Total tasks to test: {len(tasks)}")

results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
    futures = [executor.submit(test_target_poc, t, p) for t, p in tasks]
    for fut in concurrent.futures.as_completed(futures):
        res = fut.result()
        if res:
            results.append(res)

print(f"Found {len(results)} valid crashes mapped to basic blocks!")

from collections import Counter
counts = Counter(r['target_key'] for r in results)
for k, v in counts.most_common():
    print(f"  {k}: {v}")

with open('scratch/verified_candidates.json', 'w') as f:
    json.dump(results, f, indent=2)

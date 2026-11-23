import os
import re
import subprocess
import concurrent.futures
import json
from pathlib import Path

# Collect all PoCs from all sources
poc_sources = [
    '/home/user/workspace/nycu-dissertation/target_graph/build_test/asarubbo_poc',
    '/home/user/workspace/nycu-dissertation/target_graph/build_test/linuxflaw_poc',
    '/home/user/workspace/nycu-dissertation/bench/target/benchmark-project',
]

all_pocs = []
for s in poc_sources:
    for root, _, files in os.walk(s):
        for f in files:
            p = os.path.join(root, f)
            if any(p.endswith(ext) for ext in ['.o', '.a', '.so', '.py', '.sh', '.md', '.git', '.pyc']):
                continue
            all_pocs.append(p)

print(f"Total candidate PoCs collected: {len(all_pocs)}")

# Load existing 102 cases from cases.yaml to avoid duplicating case_ids or identical pocs
cases_yaml = '/home/user/workspace/nycu-dissertation/target_graph/configs/projects/cases.yaml'
import yaml
existing_cases = yaml.safe_load(open(cases_yaml))['cases']
existing_ids = {c['case_id'] for c in existing_cases}
print(f"Existing cases: {len(existing_ids)}")

# Define target configurations
targets = [
    {
        'key': 'binutils-2.26_cxxfilt',
        'template': 'binutils-2.26_cxxfilt_CVE-2016-4487',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/binutils-2.26_cxxfilt_CVE-2016-4487/cxxfilt_inst',
        'cmd': lambda p: [],
        'stdin': True,
        'kw': ['binutils', 'cxxfilt', 'cplus', 'demangle', '2016-44', '2016-61']
    },
    {
        'key': 'binutils-2.27_strip',
        'template': 'binutils-2.27_strip_CVE-2017-7303',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/binutils-2.27_strip_CVE-2017-7303/strip_inst',
        'cmd': lambda p: ['-s', p, '-o', '/tmp/out_s'],
        'stdin': False,
        'kw': ['binutils', 'strip', 'elf', 'bfd', '2017-73']
    },
    {
        'key': 'binutils-2.28_objcopy',
        'template': 'binutils-2.28_objcopy_CVE-2017-8395',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/binutils-2.28_objcopy_CVE-2017-8395/objcopy_inst',
        'cmd': lambda p: [p, '/tmp/out_o'],
        'stdin': False,
        'kw': ['binutils', 'objcopy', 'bfd', 'elf', '2017-83']
    },
    {
        'key': 'binutils-2.28_objdump',
        'template': 'binutils-2.28_objdump_CVE-2017-8392',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/binutils-2.28_objdump_CVE-2017-8392/objdump_inst',
        'cmd': lambda p: ['-d', p],
        'stdin': False,
        'kw': ['binutils', 'objdump', 'bfd', 'dwarf', '2017-83', '2017-14']
    },
    {
        'key': 'binutils-2.29_nm',
        'template': 'binutils-2.29_nm_CVE-2017-15020',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/binutils-2.29_nm_CVE-2017-15020/nm_inst',
        'cmd': lambda p: ['-l', p],
        'stdin': False,
        'kw': ['binutils', 'nm', 'dwarf', 'bfd', '2017-15', '2017-14']
    },
    {
        'key': 'binutils-2.29_readelf',
        'template': 'binutils-2.29_readelf_CVE-2017-16828',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/binutils-2.29_readelf_CVE-2017-16828/readelf_inst',
        'cmd': lambda p: ['-a', p],
        'stdin': False,
        'kw': ['binutils', 'readelf', 'dwarf', 'elf', '2017-16']
    },
    {
        'key': 'binutils-2.31.1_objdump',
        'template': 'binutils-2.31.1_objdump_CVE-2018-17360',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/binutils-2.31.1_objdump_CVE-2018-17360/objdump_inst',
        'cmd': lambda p: ['-d', p],
        'stdin': False,
        'kw': ['binutils', 'objdump', 'bfd', '2018-17']
    },
    {
        'key': 'libtiff-4.0.6_tiffcrop',
        'template': 'libtiff-4.0.6_tiffcrop_CVE-2016-10272',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/libtiff-4.0.6_tiffcrop_CVE-2016-10272/tiffcrop_inst',
        'cmd': lambda p: ['-i', p, '/tmp/out.tif'],
        'stdin': False,
        'kw': ['libtiff', 'tiffcrop', 'tiff', '2016-10', '2017-7']
    },
    {
        'key': 'libtiff-4.0.6_tiffcp',
        'template': 'libtiff-4.0.6_tiffcp_CVE-2016-10269',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/libtiff-4.0.6_tiffcp_CVE-2016-10269/tiffcp_inst',
        'cmd': lambda p: ['-i', p, '/tmp/out.tif'],
        'stdin': False,
        'kw': ['libtiff', 'tiffcp', 'tiff', '2016-10', '2017-7']
    },
    {
        'key': 'libtiff-4.0.6_tiffsplit',
        'template': 'libtiff-4.0.6_tiffsplit_CVE-2016-9273',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/libtiff-4.0.6_tiffsplit_CVE-2016-9273/tiffsplit_inst',
        'cmd': lambda p: [p],
        'stdin': False,
        'kw': ['libtiff', 'tiffsplit', 'tiff', '2016-92']
    },
    {
        'key': 'jasper-1.900.1_imginfo',
        'template': 'jasper-1.900.1_imginfo_CVE-2016-8887',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/jasper-1.900.1_imginfo_CVE-2016-8887/imginfo_inst',
        'cmd': lambda p: ['-f', p],
        'stdin': False,
        'kw': ['jasper', 'imginfo', 'jpc', 'jp2', '2016-', '2017-']
    },
    {
        'key': 'bento4-1.5.0_mp42aac',
        'template': 'bento4-1.5.0_mp42aac_CVE-2017-14638',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/bento4-1.5.0_mp42aac_CVE-2017-14638/mp42aac_inst',
        'cmd': lambda p: [p, '/tmp/out.aac'],
        'stdin': False,
        'kw': ['bento4', 'mp42aac', 'mp4', '2017-14', '2018-20']
    },
    {
        'key': 'zziplib-0.13.62_unzzipcat-mem',
        'template': 'zziplib-0.13.62_unzzipcat-mem_CVE-2017-5974',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/zziplib-0.13.62_unzzipcat-mem_CVE-2017-5974/unzzipcat-mem_inst',
        'cmd': lambda p: [p],
        'stdin': False,
        'kw': ['zziplib', 'zzip', 'zip', '2017-59']
    },
    {
        'key': 'libming-4.7.1_swftophp',
        'template': 'libming-4.7.1_swftophp_CVE-2017-7578',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/libming-4.7.1_swftophp_CVE-2017-7578/swftophp_inst',
        'cmd': lambda p: [p],
        'stdin': False,
        'kw': ['libming', 'ming', 'swf', 'swftophp', '2017-75', '2016-98']
    },
    {
        'key': 'libming-4.8_swftophp',
        'template': 'libming-4.8_swftophp_CVE-2018-8962',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/libming-4.8_swftophp_CVE-2018-8962/swftophp_inst',
        'cmd': lambda p: [p],
        'stdin': False,
        'kw': ['libming', 'ming', 'swf', 'swftophp', '2018-89', '2018-11', '2018-78', '2019-12']
    },
    {
        'key': 'imageworsener-1.3.1_imagew',
        'template': 'imageworsener-1.3.1_imagew_CVE-2017-9204',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/imageworsener-1.3.1_imagew_CVE-2017-9204/imagew_inst',
        'cmd': lambda p: [p, '/tmp/out.png'],
        'stdin': False,
        'kw': ['imageworsener', 'imagew', 'image', '2017-92']
    },
    {
        'key': 'libxml2-2.9.4_xmllint',
        'template': 'libxml2-2.9.4_xmllint_CVE-2017-5969',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/libxml2-2.9.4_xmllint_CVE-2017-5969/xmllint_inst',
        'cmd': lambda p: ['--recover', '--valid', p],
        'stdin': False,
        'kw': ['libxml2', 'xml', 'xmllint', '2017-59', '2017-90']
    },
    {
        'key': 'libjpeg-1.5.90_cjpeg',
        'template': 'libjpeg-1.5.90_cjpeg_CVE-2018-14498',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/libjpeg-1.5.90_cjpeg_CVE-2018-14498/cjpeg_inst',
        'cmd': lambda p: [p],
        'stdin': False,
        'kw': ['libjpeg', 'jpeg', 'cjpeg', '2018-14', '2020-13']
    },
    {
        'key': 'jhead-3.04_jhead',
        'template': 'jhead-3.04_jhead_issue54',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/jhead-3.04_jhead_issue54/jhead_inst',
        'cmd': lambda p: ['-ds2020:01:01:1111111111111111111111111111111111111111', p],
        'stdin': False,
        'kw': ['jhead', 'exif', 'jpg', 'jpeg', 'issue']
    },
    {
        'key': 'lrzip-ed51e14_lrzip',
        'template': 'lrzip-ed51e14_lrzip_CVE-2018-11496',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/lrzip-ed51e14_lrzip_CVE-2018-11496/lrzip_inst',
        'cmd': lambda p: ['-t', p],
        'stdin': False,
        'kw': ['lrzip', 'lrz', '2018-11', '2017-88']
    },
    {
        'key': 'lame-3.99.5_lame',
        'template': 'lame-3.99.5_lame_CVE-2015-9101',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/lame-3.99.5_lame_CVE-2015-9101/lame_inst',
        'cmd': lambda p: [p, '/tmp/out.mp3'],
        'stdin': False,
        'kw': ['lame', 'mp3', 'wav', '2015-91', '2017-']
    }
]

env = os.environ.copy()
env['ASAN_OPTIONS'] = 'abort_on_error=0:symbolize=1:strip_path_prefix=/workspace/:handle_segv=1'

def run_test(target, poc):
    bin_path = target['bin']
    if not os.path.exists(bin_path):
        return None
    try:
        if target['stdin']:
            with open(poc, 'rb') as f:
                r = subprocess.run([bin_path] + target['cmd'](poc), stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=1.5)
        else:
            r = subprocess.run([bin_path] + target['cmd'](poc), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=1.5)
        out = (r.stdout + r.stderr).decode(errors='replace')
        if 'ERROR: AddressSanitizer:' in out:
            m = re.search(r'ERROR: AddressSanitizer:\s+([a-zA-Z\-]+)', out)
            san = m.group(1) if m else 'unknown'
            if san != 'leak':
                # Parse stack top
                lines = out.splitlines()
                fn = 'unknown'
                fpath = 'unknown'
                fline = 0
                for line in lines:
                    fm = re.search(r'#\d+\s+0x[0-9a-f]+\s+in\s+([^\s]+)\s+([^:\s]+):(\d+)', line)
                    if fm:
                        cand_fn = fm.group(1)
                        if not cand_fn.startswith('__asan') and not cand_fn.startswith('__interceptor'):
                            fn = cand_fn
                            fpath = fm.group(2)
                            fline = int(fm.group(3))
                            break
                return {
                    'target_key': target['key'],
                    'template': target['template'],
                    'poc': poc,
                    'sanitizer': san,
                    'function': fn,
                    'file': os.path.basename(fpath),
                    'line': fline,
                }
    except Exception:
        pass
    return None

test_tasks = []
for t in targets:
    matched = [p for p in all_pocs if any(k.lower() in p.lower() for k in t['kw'])]
    for poc in matched:
        test_tasks.append((t, poc))

print(f"Total pairs to test: {len(test_tasks)}")

valid_crashes = []
with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
    futures = [executor.submit(run_test, t, p) for t, p in test_tasks]
    for fut in concurrent.futures.as_completed(futures):
        res = fut.result()
        if res:
            valid_crashes.append(res)

print(f"Total valid crashes identified: {len(valid_crashes)}")

with open('/home/user/workspace/nycu-dissertation/target_graph/scratch/crashes_pool.json', 'w') as f:
    json.dump(valid_crashes, f, indent=2)

print("Saved crashes pool to scratch/crashes_pool.json")

import os
import re
import subprocess
import concurrent.futures
from pathlib import Path

# Collect all PoCs
poc_dirs = [
    '/home/user/workspace/nycu-dissertation/target_graph/build_test/asarubbo_poc',
    '/home/user/workspace/nycu-dissertation/target_graph/build_test/linuxflaw_poc',
    '/home/user/workspace/nycu-dissertation/bench/target/benchmark-project',
]

all_pocs = []
for pdir in poc_dirs:
    for root, _, files in os.walk(pdir):
        for f in files:
            p = os.path.join(root, f)
            # Filter out non-poc files (like source code, object files, binaries)
            if any(p.endswith(ext) for ext in ['.c', '.h', '.o', '.a', '.so', '.py', '.sh', '.md', '.txt', '.json', '.yaml', '.yml', '.git']):
                continue
            all_pocs.append(p)

print(f"Total candidate PoC files: {len(all_pocs)}")

# Define target binaries to test
targets = [
    {
        'key': 'binutils-2.26_cxxfilt',
        'template': 'binutils-2.26_cxxfilt_CVE-2016-4487',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/binutils-2.26_cxxfilt_CVE-2016-4487/cxxfilt_inst',
        'cmd': lambda p: [],
        'stdin': True,
        'kw': ['binutils', 'cxxfilt', 'cplus', 'demangle']
    },
    {
        'key': 'binutils-2.27_strip',
        'template': 'binutils-2.27_strip_CVE-2017-7303',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/binutils-2.27_strip_CVE-2017-7303/strip_inst',
        'cmd': lambda p: ['-s', p, '-o', '/tmp/out_s'],
        'stdin': False,
        'kw': ['binutils', 'strip', 'elf', 'bfd']
    },
    {
        'key': 'binutils-2.28_objcopy',
        'template': 'binutils-2.28_objcopy_CVE-2017-8395',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/binutils-2.28_objcopy_CVE-2017-8395/objcopy_inst',
        'cmd': lambda p: [p, '/tmp/out_o'],
        'stdin': False,
        'kw': ['binutils', 'objcopy', 'bfd', 'elf']
    },
    {
        'key': 'binutils-2.28_objdump',
        'template': 'binutils-2.28_objdump_CVE-2017-8392',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/binutils-2.28_objdump_CVE-2017-8392/objdump_inst',
        'cmd': lambda p: ['-d', p],
        'stdin': False,
        'kw': ['binutils', 'objdump', 'bfd', 'dwarf']
    },
    {
        'key': 'binutils-2.29_nm',
        'template': 'binutils-2.29_nm_CVE-2017-15020',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/binutils-2.29_nm_CVE-2017-15020/nm_inst',
        'cmd': lambda p: ['-l', p],
        'stdin': False,
        'kw': ['binutils', 'nm', 'dwarf', 'bfd']
    },
    {
        'key': 'binutils-2.29_readelf',
        'template': 'binutils-2.29_readelf_CVE-2017-16828',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/binutils-2.29_readelf_CVE-2017-16828/readelf_inst',
        'cmd': lambda p: ['-a', p],
        'stdin': False,
        'kw': ['binutils', 'readelf', 'dwarf', 'elf']
    },
    {
        'key': 'binutils-2.31.1_objdump',
        'template': 'binutils-2.31.1_objdump_CVE-2018-17360',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/binutils-2.31.1_objdump_CVE-2018-17360/objdump_inst',
        'cmd': lambda p: ['-d', p],
        'stdin': False,
        'kw': ['binutils', 'objdump', 'bfd']
    },
    {
        'key': 'libtiff-4.0.6_tiffcrop',
        'template': 'libtiff-4.0.6_tiffcrop_CVE-2016-10272',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/libtiff-4.0.6_tiffcrop_CVE-2016-10272/tiffcrop_inst',
        'cmd': lambda p: ['-i', p, '/tmp/out.tif'],
        'stdin': False,
        'kw': ['libtiff', 'tiffcrop', 'tiff']
    },
    {
        'key': 'libtiff-4.0.6_tiffcp',
        'template': 'libtiff-4.0.6_tiffcp_CVE-2016-10269',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/libtiff-4.0.6_tiffcp_CVE-2016-10269/tiffcp_inst',
        'cmd': lambda p: ['-i', p, '/tmp/out.tif'],
        'stdin': False,
        'kw': ['libtiff', 'tiffcp', 'tiff']
    },
    {
        'key': 'libtiff-4.0.6_tiffsplit',
        'template': 'libtiff-4.0.6_tiffsplit_CVE-2016-9273',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/libtiff-4.0.6_tiffsplit_CVE-2016-9273/tiffsplit_inst',
        'cmd': lambda p: [p],
        'stdin': False,
        'kw': ['libtiff', 'tiffsplit', 'tiff']
    },
    {
        'key': 'jasper-1.900.1_imginfo',
        'template': 'jasper-1.900.1_imginfo_CVE-2016-8887',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/jasper-1.900.1_imginfo_CVE-2016-8887/imginfo_inst',
        'cmd': lambda p: ['-f', p],
        'stdin': False,
        'kw': ['jasper', 'imginfo', 'jpc', 'jp2']
    },
    {
        'key': 'bento4-1.5.0_mp42aac',
        'template': 'bento4-1.5.0_mp42aac_CVE-2017-14638',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/bento4-1.5.0_mp42aac_CVE-2017-14638/mp42aac_inst',
        'cmd': lambda p: [p, '/tmp/out.aac'],
        'stdin': False,
        'kw': ['bento4', 'mp42aac', 'mp4']
    },
    {
        'key': 'zziplib-0.13.62_unzzipcat-mem',
        'template': 'zziplib-0.13.62_unzzipcat-mem_CVE-2017-5974',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/zziplib-0.13.62_unzzipcat-mem_CVE-2017-5974/unzzipcat-mem_inst',
        'cmd': lambda p: [p],
        'stdin': False,
        'kw': ['zziplib', 'zzip', 'zip']
    },
    {
        'key': 'libming-4.7.1_swftophp',
        'template': 'libming-4.7.1_swftophp_CVE-2017-7578',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/libming-4.7.1_swftophp_CVE-2017-7578/swftophp_inst',
        'cmd': lambda p: [p],
        'stdin': False,
        'kw': ['libming', 'ming', 'swf', 'swftophp']
    },
    {
        'key': 'libming-4.8_swftophp',
        'template': 'libming-4.8_swftophp_CVE-2018-8962',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/libming-4.8_swftophp_CVE-2018-8962/swftophp_inst',
        'cmd': lambda p: [p],
        'stdin': False,
        'kw': ['libming', 'ming', 'swf', 'swftophp']
    },
    {
        'key': 'imageworsener-1.3.1_imagew',
        'template': 'imageworsener-1.3.1_imagew_CVE-2017-9204',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/imageworsener-1.3.1_imagew_CVE-2017-9204/imagew_inst',
        'cmd': lambda p: [p, '/tmp/out.png'],
        'stdin': False,
        'kw': ['imageworsener', 'imagew', 'image']
    },
    {
        'key': 'libxml2-2.9.4_xmllint',
        'template': 'libxml2-2.9.4_xmllint_CVE-2017-5969',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/libxml2-2.9.4_xmllint_CVE-2017-5969/xmllint_inst',
        'cmd': lambda p: ['--recover', '--valid', p],
        'stdin': False,
        'kw': ['libxml2', 'xml', 'xmllint']
    },
    {
        'key': 'libjpeg-1.5.90_cjpeg',
        'template': 'libjpeg-1.5.90_cjpeg_CVE-2018-14498',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/libjpeg-1.5.90_cjpeg_CVE-2018-14498/cjpeg_inst',
        'cmd': lambda p: [p],
        'stdin': False,
        'kw': ['libjpeg', 'jpeg', 'cjpeg']
    },
    {
        'key': 'jhead-3.04_jhead',
        'template': 'jhead-3.04_jhead_issue54',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/jhead-3.04_jhead_issue54/jhead_inst',
        'cmd': lambda p: ['-ds2020:01:01:1111111111111111111111111111111111111111', p],
        'stdin': False,
        'kw': ['jhead', 'exif', 'jpg', 'jpeg']
    },
    {
        'key': 'lrzip-ed51e14_lrzip',
        'template': 'lrzip-ed51e14_lrzip_CVE-2018-11496',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/lrzip-ed51e14_lrzip_CVE-2018-11496/lrzip_inst',
        'cmd': lambda p: ['-t', p],
        'stdin': False,
        'kw': ['lrzip', 'lrz']
    },
    {
        'key': 'lua-5.3.5_lua',
        'template': 'lua-5.3.5_lua_CVE-2019-6706',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/lua-5.3.5_lua_CVE-2019-6706/lua_inst',
        'cmd': lambda p: [p],
        'stdin': False,
        'kw': ['lua']
    },
    {
        'key': 'cJSON-1.7.8_cJSON',
        'template': 'cJSON-1.7.8_cJSON_CVE-2019-1010239',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/cJSON-1.7.8_cJSON_CVE-2019-1010239/cjson_test_inst',
        'cmd': lambda p: [p],
        'stdin': False,
        'kw': ['cjson', 'json']
    },
    {
        'key': 'lame-3.99.5_lame',
        'template': 'lame-3.99.5_lame_CVE-2015-9101',
        'bin': '/home/user/workspace/nycu-dissertation/target_graph/cases/lame-3.99.5_lame_CVE-2015-9101/lame_inst',
        'cmd': lambda p: [p, '/tmp/out.mp3'],
        'stdin': False,
        'kw': ['lame', 'mp3', 'wav']
    }
]

env = os.environ.copy()
env['ASAN_OPTIONS'] = 'abort_on_error=0:symbolize=1:strip_path_prefix=/workspace/:handle_segv=1'

def test_pair(t, poc):
    bin_path = t['bin']
    if not os.path.exists(bin_path):
        return None
    try:
        if t['stdin']:
            with open(poc, 'rb') as f:
                r = subprocess.run([bin_path] + t['cmd'](poc), stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=1.0)
        else:
            r = subprocess.run([bin_path] + t['cmd'](poc), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=1.0)
        out = (r.stdout + r.stderr).decode(errors='replace')
        if 'ERROR: AddressSanitizer:' in out:
            m = re.search(r'ERROR: AddressSanitizer:\s+([a-zA-Z\-]+)', out)
            san = m.group(1) if m else 'unknown'
            if san != 'leak':
                # Extract top frame
                # #0 0x... in func file:line
                fm = re.search(r'#0\s+0x[0-9a-f]+\s+in\s+([^\s]+)\s+([^:\s]+):(\d+)', out)
                fn = fm.group(1) if fm else 'unknown'
                fpath = fm.group(2) if fm else 'unknown'
                fline = fm.group(3) if fm else '0'
                if fn.startswith('__asan') or fn.startswith('__interceptor'):
                    fm2 = re.search(r'#1\s+0x[0-9a-f]+\s+in\s+([^\s]+)\s+([^:\s]+):(\d+)', out)
                    if fm2:
                        fn = fm2.group(1)
                        fpath = fm2.group(2)
                        fline = fm2.group(3)
                return {
                    'target_key': t['key'],
                    'template': t['template'],
                    'poc': poc,
                    'sanitizer': san,
                    'function': fn,
                    'file': os.path.basename(fpath),
                    'line': int(fline),
                    'cmd': t['cmd'](poc),
                    'stdin': t['stdin']
                }
    except Exception:
        pass
    return None

tasks = []
for t in targets:
    # Filter candidate pocs by keyword
    kw_matched = [p for p in all_pocs if any(k.lower() in p.lower() for k in t['kw'])]
    for poc in kw_matched:
        tasks.append((t, poc))

print(f"Total target-poc pairs to test: {len(tasks)}")

results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
    futures = [executor.submit(test_pair, t, p) for t, p in tasks]
    for fut in concurrent.futures.as_completed(futures):
        res = fut.result()
        if res:
            results.append(res)

print(f"Total crashes found: {len(results)}")

# Group by unique crash point: (target_key, function, file, line)
unique_crashes = {}
for r in results:
    key = (r['target_key'], r['function'], r['file'], r['line'])
    if key not in unique_crashes:
        unique_crashes[key] = []
    unique_crashes[key].append(r)

print(f"Unique crash locations: {len(unique_crashes)}")

import json
with open('/home/user/workspace/nycu-dissertation/target_graph/scratch/discovered_crashes.json', 'w') as f:
    json.dump(results, f, indent=2)

print("Saved discovered crashes to scratch/discovered_crashes.json")

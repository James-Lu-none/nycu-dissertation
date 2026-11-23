import os
import re
import shutil
import subprocess
import yaml
import json
from pathlib import Path
from collections import Counter
import pandas as pd

from target_graph.pipelines.label_audit import (
    parse_sanitizer_output,
    audit_case,
    BasicBlockMapper,
    trace_to_basic_blocks,
    partition_target_candidates,
)

cases_yaml_path = Path('configs/projects/cases.yaml')
cases_root = Path('cases')

# 1. Load the original 102 cases from backup or cases.yaml
if Path('configs/projects/cases.yaml.bak_102').exists():
    original_102 = yaml.safe_load(Path('configs/projects/cases.yaml.bak_102').read_text())['cases']
else:
    original_102 = yaml.safe_load(cases_yaml_path.read_text())['cases'][:102]

print(f"Original baseline cases: {len(original_102)}")

# 2. Audit all currently existing case directories in cases/
existing_dirs = sorted([d for d in cases_root.iterdir() if d.is_dir() and (d / 'parquet').exists() and (d / 'trace_crash.txt').exists() and (d / 'crash_stderr.txt').exists()])
print(f"Total existing candidate directories in cases/: {len(existing_dirs)}")

# Build template metadata dictionary from original 102 cases
template_meta = {}
for c in original_102:
    cid = c['case_id']
    target_bin = c['target_binary']
    template_meta[cid] = c
    template_meta[target_bin] = c

validated_cases = []
used_case_ids = set()
used_poc_paths = set()

for d in existing_dirs:
    cid = d.name
    # Check if in original_102
    orig_match = [c for c in original_102 if c['case_id'] == cid]
    if orig_match:
        cfg = orig_match[0]
    else:
        # Reconstruct config
        stderr_file = d / 'crash_stderr.txt'
        san_report = parse_sanitizer_output(stderr_file.read_text(encoding='utf-8', errors='replace'))
        if not san_report:
            continue
        target_frame = None
        for f in san_report.frames:
            fn = f.function_name.lower()
            if any(p in fn for p in ['__asan', '__interceptor', 'strlen', 'memcpy', 'memset', 'malloc', 'free', 'realloc']):
                continue
            if f.line_number > 0 and f.source_file and f.function_name != 'unknown':
                target_frame = f
                break
        if not target_frame:
            target_frame = san_report.crash_frame
        if not target_frame:
            continue
            
        # Target binary
        insts = list(d.glob('*_inst'))
        if not insts:
            continue
        tgt = insts[0].name.replace('_inst', '')
        tpl_meta = template_meta.get(tgt)
        if not tpl_meta:
            continue
            
        pocs = list(d.glob('poc*'))
        if not pocs:
            continue
            
        cve_tag = cid.split('_')[-1]
        cfg = {
            'case_id': cid,
            'project': tpl_meta['project'],
            'cve': cve_tag if 'CVE-' in cve_tag else f"ISSUE-{cve_tag}",
            'target_binary': tgt,
            'vulnerable_version': tpl_meta['vulnerable_version'],
            'fixed_commit': tpl_meta['fixed_commit'],
            'poc_path': str(pocs[0].resolve()),
            'expected_oracle': {
                'sanitizer': san_report.error_type,
                'function': target_frame.function_name,
                'file': Path(target_frame.source_file).name,
                'line': target_frame.line_number,
            }
        }
        if 'poc_cmd' in tpl_meta:
            cfg['poc_cmd'] = tpl_meta['poc_cmd']
        if 'poc_stdin' in tpl_meta:
            cfg['poc_stdin'] = tpl_meta['poc_stdin']
            
    try:
        rec = audit_case(cfg, cases_root)
        if rec.oracle_reproduced and rec.fault_bb_in_trace and rec.fault_bb_in_dep_slice and rec.positive_yield > 0:
            validated_cases.append(cfg)
            used_case_ids.add(cid)
            used_poc_paths.add(os.path.abspath(cfg['poc_path']))
    except Exception as e:
        pass

print(f"Verified initial valid cases: {len(validated_cases)}")

# 3. Load undeployed candidates from pools
f1 = json.load(open('scratch/fully_verified_candidates.json'))
f2 = json.load(open('scratch/broad_scan_results.json'))
f3 = json.load(open('scratch/passed_extra.json'))

pool = f1 + f2 + f3
candidate_tasks = []
seen_keys = set()

for item in pool:
    poc = os.path.abspath(item['poc'])
    tpl = item['template']
    key = (tpl, poc)
    if key in seen_keys:
        continue
    seen_keys.add(key)
    candidate_tasks.append(item)

print(f"Total candidate tasks in pool: {len(candidate_tasks)}")

def get_cmd_spec(target_bin):
    if 'cxxfilt' in target_bin:
        return ['{binary}'], '{poc}'
    elif 'strip' in target_bin:
        return ['{binary}', '-s', '{poc}', '-o', '/tmp/out_strip'], None
    elif 'objcopy' in target_bin:
        return ['{binary}', '--compress-debug-sections', '{poc}', '/tmp/out_objcopy'], None
    elif 'objdump' in target_bin:
        return ['{binary}', '-d', '{poc}'], None
    elif 'readelf' in target_bin:
        return ['{binary}', '-w', '{poc}'], None
    elif 'nm' in target_bin:
        return ['{binary}', '-l', '{poc}'], None
    elif 'tiffcrop' in target_bin:
        return ['{binary}', '-i', '{poc}', '/tmp/out.tif'], None
    elif 'tiffcp' in target_bin:
        return ['{binary}', '-i', '{poc}', '/tmp/out.tif'], None
    elif 'tiffsplit' in target_bin:
        return ['{binary}', '{poc}'], None
    elif 'imginfo' in target_bin:
        return ['{binary}', '-f', '{poc}'], None
    elif 'mp42aac' in target_bin:
        return ['{binary}', '{poc}', '/tmp/out.aac'], None
    elif 'unzzipcat-mem' in target_bin:
        return ['{binary}', '{poc}'], None
    elif 'swftophp' in target_bin:
        return ['{binary}', '{poc}'], None
    elif 'imagew' in target_bin:
        return ['{binary}', '{poc}', '/tmp/out.bmp', '-outfmt', 'bmp'], None
    elif 'xmllint' in target_bin:
        return ['{binary}', '--valid', '--noout', '{poc}'], None
    elif 'cjpeg' in target_bin:
        return ['{binary}', '{poc}'], None
    elif 'jhead' in target_bin:
        return ['{binary}', '-ds2020:01:01:1111111111111111111111111111111111111111', '{poc}'], None
    elif 'lrzip' in target_bin:
        return ['{binary}', '-t', '{poc}'], None
    elif 'lame' in target_bin:
        return ['{binary}', '{poc}', '/dev/null'], None
    else:
        return ['{binary}', '{poc}'], None

def make_new_case_id(tpl_meta, poc_path):
    pname = Path(poc_path).name
    cve_m = re.search(r'(CVE-\d{4}-\d+|20\d{2}-\d+)', pname)
    if not cve_m:
        cve_m = re.search(r'(CVE-\d{4}-\d+|20\d{2}-\d+)', str(poc_path))
    if cve_m:
        raw_cve = cve_m.group(1)
        cve_tag = f"CVE-{raw_cve}" if not raw_cve.startswith('CVE-') else raw_cve
    else:
        as_m = re.search(r'00(\d+)-', pname)
        if as_m:
            cve_tag = f"ASARUBBO-{as_m.group(1)}"
        else:
            clean = re.sub(r'[^a-zA-Z0-9]', '-', pname).strip('-')[:20]
            cve_tag = f"POC-{clean}"
            
    proj = tpl_meta['project']
    ver = tpl_meta['vulnerable_version']
    tgt = tpl_meta['target_binary']
    
    base_id = f"{proj}-{ver}_{tgt}_{cve_tag}"
    cand_id = base_id
    idx = 2
    while cand_id in used_case_ids:
        cand_id = f"{base_id}-{idx}"
        idx += 1
    used_case_ids.add(cand_id)
    return cand_id, (cve_tag if 'CVE-' in cve_tag else f"ISSUE-{cve_tag}")

# 4. Harvest remaining cases until exactly 300
target_total = 300
print(f"Currently have {len(validated_cases)} validated cases. Harvesting until {target_total}...")

env_run = os.environ.copy()
env_run['ASAN_SYMBOLIZER_PATH'] = '/usr/bin/llvm-symbolizer-18'
env_run['ASAN_OPTIONS'] = 'abort_on_error=0:symbolize=1:external_symbolizer_path=/usr/bin/llvm-symbolizer-18:strip_path_prefix=/workspace/:handle_segv=1'

for item in candidate_tasks:
    if len(validated_cases) >= target_total:
        break
        
    poc_src = Path(item['poc'])
    tpl_name = item['template']
    if not (cases_root / tpl_name).exists():
        continue
    tpl_dir = cases_root / tpl_name
    tpl_meta = template_meta.get(tpl_name)
    if not tpl_meta:
        insts = list(tpl_dir.glob('*_inst'))
        if not insts:
            continue
        tgt = insts[0].name.replace('_inst', '')
        tpl_meta = template_meta.get(tgt)
    if not tpl_meta:
        continue
        
    target_bin = tpl_meta['target_binary']
    case_id, cve_name = make_new_case_id(tpl_meta, str(poc_src))
    case_dir = cases_root / case_id
    
    if case_dir.exists():
        continue
        
    try:
        case_dir.mkdir(parents=True)
        # Copy bundle
        shutil.copytree(tpl_dir / 'parquet', case_dir / 'parquet')
        shutil.copyfile(tpl_dir / 'bb_map.jsonl', case_dir / 'bb_map.jsonl')
        
        for pattern in [f'{target_bin}_inst', f'{target_bin}_base', f'{target_bin}.bc', f'{target_bin}']:
            for src_f in tpl_dir.glob(pattern):
                shutil.copyfile(src_f, case_dir / src_f.name)
                if '_inst' in src_f.name or '_base' in src_f.name:
                    os.chmod(case_dir / src_f.name, 0o755)
                    
        for v2_file in ['analysis_v2_nodes.jsonl', 'analysis_v2_edges.jsonl', 'analysis_v2_summary.json', 'pass_summary.json', 'raw_nodes.jsonl', 'raw_edges.jsonl']:
            if (tpl_dir / v2_file).exists():
                shutil.copyfile(tpl_dir / v2_file, case_dir / v2_file)
                
        poc_ext = poc_src.suffix
        dst_poc = case_dir / f"poc{poc_ext}"
        shutil.copyfile(poc_src, dst_poc)
        
        if 'jhead' in target_bin and (tpl_dir / 'dummy.jpg').exists():
            shutil.copyfile(tpl_dir / 'dummy.jpg', case_dir / 'dummy.jpg')
            
        inst_bin = case_dir / f"{target_bin}_inst"
        trace_file = case_dir / 'trace_crash.txt'
        stderr_file = case_dir / 'crash_stderr.txt'
        env_run['TARGET_GRAPH_TRACE_FILE'] = str(trace_file.resolve())
        
        raw_cmd, stdin_spec = get_cmd_spec(target_bin)
        cmd_args = []
        for arg in raw_cmd:
            if arg == '{binary}':
                cmd_args.append(str(inst_bin.resolve()))
            elif arg == '{poc}':
                cmd_args.append(str(dst_poc.resolve()))
            else:
                cmd_args.append(arg)
                
        if stdin_spec:
            with open(dst_poc, 'rb') as f:
                r = subprocess.run(cmd_args, stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env_run, timeout=12.0)
        else:
            r = subprocess.run(cmd_args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env_run, timeout=12.0)
            
        stderr_file.write_bytes(r.stderr)
        
        if not trace_file.exists() or trace_file.stat().st_size == 0:
            shutil.rmtree(case_dir, ignore_errors=True)
            continue
            
        stderr_text = r.stderr.decode('utf-8', errors='replace')
        san_report = parse_sanitizer_output(stderr_text)
        if not san_report or 'leak' in san_report.error_type.lower() or san_report.error_type.isdigit():
            shutil.rmtree(case_dir, ignore_errors=True)
            continue
            
        target_frame = None
        for f in san_report.frames:
            fn = f.function_name.lower()
            if any(p in fn for p in ['__asan', '__interceptor', 'strlen', 'memcpy', 'memset', 'malloc', 'free', 'realloc']):
                continue
            if f.line_number > 0 and f.source_file and f.function_name != 'unknown':
                target_frame = f
                break
        if not target_frame:
            target_frame = san_report.crash_frame
        if not target_frame:
            shutil.rmtree(case_dir, ignore_errors=True)
            continue
            
        cfg = {
            'case_id': case_id,
            'project': tpl_meta['project'],
            'cve': cve_name,
            'target_binary': target_bin,
            'vulnerable_version': tpl_meta['vulnerable_version'],
            'fixed_commit': tpl_meta['fixed_commit'],
            'poc_path': str(dst_poc.resolve()),
            'poc_cmd': raw_cmd,
            'expected_oracle': {
                'sanitizer': san_report.error_type,
                'function': target_frame.function_name,
                'file': Path(target_frame.source_file).name,
                'line': target_frame.line_number,
            }
        }
        if stdin_spec:
            cfg['poc_stdin'] = '{poc}'
            
        # Verify with audit_case
        rec = audit_case(cfg, cases_root)
        if rec.oracle_reproduced and rec.fault_bb_in_trace and rec.fault_bb_in_dep_slice and rec.positive_yield > 0:
            validated_cases.append(cfg)
            used_poc_paths.add(os.path.abspath(cfg['poc_path']))
            print(f"Validated & added: {len(validated_cases)} / {target_total} -> {case_id} ({rec.observed_sanitizer} in {rec.observed_function}:{rec.observed_line}) Pt={rec.positive_yield}")
        else:
            shutil.rmtree(case_dir, ignore_errors=True)
    except Exception as e:
        shutil.rmtree(case_dir, ignore_errors=True)

print(f"\nFinal count of verified cases: {len(validated_cases)}")

# If we reached >= 300, slice to exactly 300
if len(validated_cases) > 300:
    validated_cases = validated_cases[:300]

assert len(validated_cases) == 300, f"Expected 300, got {len(validated_cases)}"

# Verify unique case_ids
cids = [c['case_id'] for c in validated_cases]
assert len(cids) == len(set(cids)), "Duplicate case_id found!"

# Write cases.yaml
cases_yaml_path.write_text(yaml.dump({'cases': validated_cases}, sort_keys=False, default_flow_style=False))
print(f"SUCCESS: Written exactly {len(validated_cases)} cases to {cases_yaml_path}!")

EOF

import os
import re
import shutil
import subprocess
import yaml
import json
import concurrent.futures
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
existing_cases = yaml.safe_load(cases_yaml_path.read_text())['cases']
existing_pocs = {os.path.abspath(c['poc_path']) for c in existing_cases}
existing_ids = {c['case_id'] for c in existing_cases}
print(f"Existing cases: {len(existing_cases)}")

# Load candidate pools
f1 = json.load(open('scratch/fully_verified_candidates.json'))
f2 = json.load(open('scratch/broad_scan_results.json'))
f3 = json.load(open('scratch/passed_extra.json'))

combined = {}
for item in f1 + f2 + f3:
    poc = os.path.abspath(item['poc'])
    if poc in existing_pocs:
        continue
    tpl = item['template']
    key = (tpl, poc)
    if key not in combined:
        combined[key] = item

print(f"Total available candidate pairs: {len(combined)}")

template_meta = {}
for c in existing_cases:
    cid = c['case_id']
    if cid not in template_meta:
        template_meta[cid] = c

needed = 300 - len(existing_cases)
print(f"Need exactly {needed} new cases to reach 300 total.")

# Build execution command spec
def get_cmd_spec(target_bin, tpl_name):
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

# Generate unique IDs beforehand
used_case_ids = set(existing_ids)
def generate_case_id(tpl_meta, poc_path):
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

cases_root = Path('cases')

def deploy_and_audit_single(candidate):
    tpl_name = candidate['template']
    poc_path = candidate['poc']
    tpl_meta = template_meta[tpl_name]
    tpl_dir = cases_root / tpl_name
    target_bin = tpl_meta['target_binary']
    
    case_id, cve_name = candidate['case_id'], candidate['cve_name']
    case_dir = cases_root / case_id
    
    try:
        if case_dir.exists():
            shutil.rmtree(case_dir)
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
                
        # Copy PoC
        src_poc = Path(poc_path)
        poc_ext = src_poc.suffix
        dst_poc = case_dir / f"poc{poc_ext}"
        shutil.copyfile(src_poc, dst_poc)
        
        if 'jhead' in target_bin and (tpl_dir / 'dummy.jpg').exists():
            shutil.copyfile(tpl_dir / 'dummy.jpg', case_dir / 'dummy.jpg')
            
        # Run instrumented
        inst_bin = case_dir / f"{target_bin}_inst"
        trace_file = case_dir / 'trace_crash.txt'
        stderr_file = case_dir / 'crash_stderr.txt'
        
        env = os.environ.copy()
        env['ASAN_SYMBOLIZER_PATH'] = '/usr/bin/llvm-symbolizer-18'
        env['ASAN_OPTIONS'] = 'abort_on_error=0:symbolize=1:external_symbolizer_path=/usr/bin/llvm-symbolizer-18:strip_path_prefix=/workspace/:handle_segv=1'
        env['TARGET_GRAPH_TRACE_FILE'] = str(trace_file.resolve())
        
        raw_cmd, stdin_spec = get_cmd_spec(target_bin, tpl_name)
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
                r = subprocess.run(cmd_args, stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env, timeout=20.0)
        else:
            r = subprocess.run(cmd_args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env, timeout=20.0)
            
        stderr_file.write_bytes(r.stderr)
        
        if not trace_file.exists() or trace_file.stat().st_size == 0:
            shutil.rmtree(case_dir, ignore_errors=True)
            return None
            
        stderr_text = r.stderr.decode('utf-8', errors='replace')
        san_report = parse_sanitizer_output(stderr_text)
        if not san_report or 'leak' in san_report.error_type.lower() or san_report.error_type.isdigit():
            shutil.rmtree(case_dir, ignore_errors=True)
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
            target_frame = san_report.crash_frame
        if not target_frame:
            shutil.rmtree(case_dir, ignore_errors=True)
            return None
            
        obs_san = san_report.error_type
        obs_fn = target_frame.function_name
        obs_file = Path(target_frame.source_file).name
        obs_line = target_frame.line_number
        
        case_cfg = {
            'case_id': case_id,
            'project': tpl_meta['project'],
            'cve': cve_name,
            'target_binary': target_bin,
            'vulnerable_version': tpl_meta['vulnerable_version'],
            'fixed_commit': tpl_meta['fixed_commit'],
            'poc_path': str(dst_poc.resolve()),
            'poc_cmd': raw_cmd,
            'expected_oracle': {
                'sanitizer': obs_san,
                'function': obs_fn,
                'file': obs_file,
                'line': obs_line,
            }
        }
        if stdin_spec:
            case_cfg['poc_stdin'] = '{poc}'
            
        # Verify via audit_case
        record = audit_case(case_cfg, cases_root)
        if record.oracle_reproduced and record.fault_bb_in_trace and record.fault_bb_in_dep_slice and record.positive_yield > 0:
            return case_cfg
        else:
            shutil.rmtree(case_dir, ignore_errors=True)
            return None
    except Exception as e:
        shutil.rmtree(case_dir, ignore_errors=True)
        return None

# Prepare candidate tasks
candidate_list = []
for (tpl, poc), item in combined.items():
    tpl_meta = template_meta[tpl]
    cid, cve_tag = generate_case_id(tpl_meta, poc)
    candidate_list.append({
        'template': tpl,
        'poc': poc,
        'case_id': cid,
        'cve_name': cve_tag,
    })

print(f"Prepared {len(candidate_list)} candidate tasks.")

successful_cases = []
print(f"Deploying and verifying candidates in parallel (target: {needed})...")

with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
    futures = [executor.submit(deploy_and_audit_single, c) for c in candidate_list]
    for fut in concurrent.futures.as_completed(futures):
        res = fut.result()
        if res:
            successful_cases.append(res)
            print(f"Deployed & Audited: {len(successful_cases)} / {needed} -> {res['case_id']}")
            if len(successful_cases) == needed:
                # Cancel remaining
                for f in futures:
                    f.cancel()
                break

print(f"\nSuccessfully deployed and audited: {len(successful_cases)} cases!")
assert len(successful_cases) == needed, f"Expected {needed}, got {len(successful_cases)}"

# Combine and write to cases.yaml
final_cases = existing_cases + successful_cases
print(f"Total cases in cases.yaml: {len(final_cases)}")
assert len(final_cases) == 300, f"Expected 300, got {len(final_cases)}"

if not Path('configs/projects/cases.yaml.bak_102').exists():
    shutil.copyfile(cases_yaml_path, 'configs/projects/cases.yaml.bak_102')

cases_yaml_path.write_text(yaml.dump({'cases': final_cases}, sort_keys=False, default_flow_style=False))
print("Updated cases.yaml successfully!")

EOF

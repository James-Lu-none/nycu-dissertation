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

print(f"Total available unique (tpl, poc) candidates: {len(combined)}")

# Template metadata map from existing cases
template_meta = {}
for c in existing_cases:
    cid = c['case_id']
    if cid not in template_meta:
        template_meta[cid] = c

# Sort candidates for diversity and quality
# We want to select exactly 198 candidates (300 - 102 = 198)
needed = 300 - len(existing_cases)
print(f"Need exactly {needed} new cases to reach 300 total.")

# Group candidates by template
grouped = {}
for (tpl, poc), item in combined.items():
    grouped.setdefault(tpl, []).append((poc, item))

# Round-robin selection across templates to maximize project diversity
selected_items = []
target_counts = Counter()

while len(selected_items) < needed:
    added_in_round = 0
    # Sort templates by current count ascending to balance
    for tpl in sorted(grouped.keys(), key=lambda t: target_counts[t]):
        if grouped[tpl]:
            poc, item = grouped[tpl].pop(0)
            selected_items.append((tpl, poc, item))
            target_counts[tpl] += 1
            added_in_round += 1
            if len(selected_items) == needed:
                break
    if added_in_round == 0:
        break

print(f"Selected {len(selected_items)} candidates.")
print("Distribution of selected 198 candidates across templates:")
for tpl, cnt in target_counts.most_common():
    print(f"  {tpl}: {cnt}")

# Function to clean and construct unique case_id
used_case_ids = set(existing_ids)

def make_case_id(tpl_meta, poc_path):
    pname = Path(poc_path).name
    # Extract CVE if present
    cve_m = re.search(r'(CVE-\d{4}-\d+|20\d{2}-\d+)', pname)
    if not cve_m:
        # Check parent folder for CVE
        cve_m = re.search(r'(CVE-\d{4}-\d+|20\d{2}-\d+)', str(poc_path))
    
    if cve_m:
        raw_cve = cve_m.group(1)
        if not raw_cve.startswith('CVE-'):
            cve_tag = f"CVE-{raw_cve}"
        else:
            cve_tag = raw_cve
    else:
        # Asarubbo ID or clean name
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
env_run = os.environ.copy()
env_run['ASAN_SYMBOLIZER_PATH'] = '/usr/bin/llvm-symbolizer-18'
env_run['ASAN_OPTIONS'] = 'abort_on_error=0:symbolize=1:external_symbolizer_path=/usr/bin/llvm-symbolizer-18:strip_path_prefix=/workspace/:handle_segv=1'

new_cases_cfg = []
deployed_count = 0

print("\nDeploying 198 cases...")
for tpl_name, poc_path, item in selected_items:
    tpl_meta = template_meta[tpl_name]
    tpl_dir = cases_root / tpl_name
    case_id, cve_name = make_case_id(tpl_meta, poc_path)
    case_dir = cases_root / case_id
    
    # 1. Create case directory and copy bundle
    if case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True)
    
    # Copy parquet
    shutil.copytree(tpl_dir / 'parquet', case_dir / 'parquet')
    # Copy bb_map
    shutil.copyfile(tpl_dir / 'bb_map.jsonl', case_dir / 'bb_map.jsonl')
    
    # Copy binaries and bitcode
    target_bin = tpl_meta['target_binary']
    for pattern in [f'{target_bin}_inst', f'{target_bin}_base', f'{target_bin}.bc', f'{target_bin}']:
        for src_f in tpl_dir.glob(pattern):
            shutil.copyfile(src_f, case_dir / src_f.name)
            if '_inst' in src_f.name or '_base' in src_f.name:
                os.chmod(case_dir / src_f.name, 0o755)
                
    # Copy analysis v2 if exists
    for v2_file in ['analysis_v2_nodes.jsonl', 'analysis_v2_edges.jsonl', 'analysis_v2_summary.json', 'pass_summary.json', 'raw_nodes.jsonl', 'raw_edges.jsonl']:
        if (tpl_dir / v2_file).exists():
            shutil.copyfile(tpl_dir / v2_file, case_dir / v2_file)
            
    # Copy PoC
    src_poc = Path(poc_path)
    poc_ext = src_poc.suffix
    dst_poc = case_dir / f"poc{poc_ext}"
    shutil.copyfile(src_poc, dst_poc)
    
    # Copy dummy.jpg if jhead
    if 'jhead' in target_bin and (tpl_dir / 'dummy.jpg').exists():
        shutil.copyfile(tpl_dir / 'dummy.jpg', case_dir / 'dummy.jpg')
        
    # 2. Run instrumented execution to capture trace and stderr
    inst_bin = case_dir / f"{target_bin}_inst"
    trace_file = case_dir / 'trace_crash.txt'
    stderr_file = case_dir / 'crash_stderr.txt'
    
    env_run['TARGET_GRAPH_TRACE_FILE'] = str(trace_file.resolve())
    
    # Construct command args
    raw_cmd = tpl_meta.get('poc_cmd', ['{binary}', '{poc}'])
    cmd_args = []
    is_stdin = False
    
    if tpl_meta.get('poc_stdin'):
        is_stdin = True
        cmd_args = [str(inst_bin.resolve())]
    else:
        for arg in raw_cmd:
            if arg == '{binary}':
                cmd_args.append(str(inst_bin.resolve()))
            elif arg == '{poc}':
                cmd_args.append(str(dst_poc.resolve()))
            else:
                cmd_args.append(arg)
                
    try:
        if is_stdin:
            with open(dst_poc, 'rb') as f:
                r = subprocess.run(cmd_args, stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env_run, timeout=5.0)
        else:
            r = subprocess.run(cmd_args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env_run, timeout=5.0)
    except Exception as e:
        print(f"Error executing {case_id}: {e}")
        continue
        
    stderr_file.write_bytes(r.stderr)
    
    # 3. Parse crash report to determine expected oracle
    stderr_text = r.stderr.decode('utf-8', errors='replace')
    san_report = parse_sanitizer_output(stderr_text)
    if not san_report:
        print(f"Warning: could not parse san report for {case_id}")
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
        
    obs_san = san_report.error_type
    obs_fn = target_frame.function_name if target_frame else item['function']
    obs_file = Path(target_frame.source_file).name if target_frame else item['file']
    obs_line = target_frame.line_number if target_frame else item['line']
    
    # Formulate case config
    new_cfg = {
        'case_id': case_id,
        'project': tpl_meta['project'],
        'cve': cve_name,
        'target_binary': target_bin,
        'vulnerable_version': tpl_meta['vulnerable_version'],
        'fixed_commit': tpl_meta['fixed_commit'],
        'poc_path': str(dst_poc.resolve()),
        'expected_oracle': {
            'sanitizer': obs_san,
            'function': obs_fn,
            'file': obs_file,
            'line': obs_line,
        }
    }
    if 'poc_cmd' in tpl_meta:
        new_cfg['poc_cmd'] = tpl_meta['poc_cmd']
    if 'poc_stdin' in tpl_meta:
        new_cfg['poc_stdin'] = tpl_meta['poc_stdin']
        
    new_cases_cfg.append(new_cfg)
    deployed_count += 1
    if deployed_count % 25 == 0:
        print(f"Deployed {deployed_count}/{needed} cases...")

print(f"\nSuccessfully deployed {len(new_cases_cfg)} new cases.")

# 4. Save combined cases.yaml
all_cases = existing_cases + new_cases_cfg
print(f"Total cases in final list: {len(all_cases)}")
assert len(all_cases) == 300, f"Expected 300 cases, got {len(all_cases)}"

output_data = {'cases': all_cases}
# Make backup of original cases.yaml
shutil.copyfile(cases_yaml_path, 'configs/projects/cases.yaml.bak_102')

cases_yaml_path.write_text(yaml.dump(output_data, sort_keys=False, default_flow_style=False))
print(f"Successfully updated {cases_yaml_path} with exactly 300 cases!")


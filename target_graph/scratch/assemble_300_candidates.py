import os
import re
import subprocess
import json
import yaml
from pathlib import Path
from collections import Counter

# 1. Load existing 102 cases
cases_yaml_path = Path('/home/user/workspace/nycu-dissertation/target_graph/configs/projects/cases.yaml')
existing_data = yaml.safe_load(cases_yaml_path.read_text())
existing_cases = existing_data['cases']
existing_ids = {c['case_id'] for c in existing_cases}
existing_pocs = {os.path.abspath(c['poc_path']) for c in existing_cases}
print(f"Existing cases: {len(existing_cases)}")

# 2. Load discovered pools
crashes_pool_file = Path('/home/user/workspace/nycu-dissertation/target_graph/scratch/fresh_crashes_pool.json')
pool = json.loads(crashes_pool_file.read_text()) if crashes_pool_file.exists() else []

# Also load from discovered_crashes.json
disc_file = Path('/home/user/workspace/nycu-dissertation/target_graph/scratch/discovered_crashes.json')
disc = json.loads(disc_file.read_text()) if disc_file.exists() else []

# Merge into unified candidates
raw_candidates = []
seen = set()

for c in pool + disc:
    p = os.path.abspath(c['poc'])
    # template case id
    t_cid = c.get('template_case_id') or c.get('template')
    key = (t_cid, p)
    if key in seen:
        continue
    seen.add(key)
    raw_candidates.append(c)

print(f"Total raw crash candidates: {len(raw_candidates)}")

# Filter out crashes that are already in existing_cases
filtered = []
for c in raw_candidates:
    p = os.path.abspath(c['poc'])
    pname = os.path.basename(p)
    if p in existing_pocs:
        continue
    # skip if function is unknown or line is 0
    fn = c.get('function', 'unknown')
    fl = c.get('line', 0)
    if fn == 'unknown' or fl == 0:
        continue
    filtered.append(c)

print(f"Filtered valid crashes with clear stack frames: {len(filtered)}")

by_proj = Counter(c.get('project') or c.get('target_key', '').split('-')[0] for c in filtered)
for pr, cnt in by_proj.most_common():
    print(f"  {pr}: {cnt}")

with open('/home/user/workspace/nycu-dissertation/target_graph/scratch/valid_filtered_candidates.json', 'w') as f:
    json.dump(filtered, f, indent=2)

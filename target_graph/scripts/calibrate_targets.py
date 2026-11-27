#!/usr/bin/env python3
"""calibrate_targets.py - Calibrate canonical target instruction for benchmark cases.

Finds the exact LLVM instruction corresponding to the crash oracle (matching
function and line, and valid in SVFG value-flow graph).
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent


def get_canonical_provenance(case_dir: Path, bc_name: str) -> Tuple[str, str]:
    cmd = [
        sys.executable, "-m", "target_graph.svf.provenance",
        "--pass-summary", str(case_dir / "pass_summary.json"),
        "--bitcode-name", bc_name,
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{ROOT_DIR}/src:{env.get('PYTHONPATH', '')}"
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True, env=env)
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return lines[0], lines[1]


def ensure_tagged_bc(case_id: str, case_dir: Path, bc_name: str, build_id: str, module_name: str, image: str = "target-graph:svf-llvm14") -> None:
    out_dir = case_dir / "svf_backend"
    out_dir.mkdir(parents=True, exist_ok=True)
    tagged_bc = out_dir / "tagged.bc"
    before_jsonl = out_dir / "before.jsonl"
    if tagged_bc.is_file() and before_jsonl.is_file() and before_jsonl.stat().st_size > 0:
        return

    c_script = f"""
set -euo pipefail
out="/workspace/cases/{case_id}/svf_backend"
bc="/workspace/cases/{case_id}/{bc_name}"
plugin=/usr/local/lib/DGIdentityPass.so
opt -load-pass-plugin="$plugin" -passes=dg-tag -o "$out/tagged.bc" "$bc"
TARGET_GRAPH_DG_EXPORT="$out/before.jsonl" opt -load-pass-plugin="$plugin" -passes=dg-export -disable-output "$out/tagged.bc"
"""
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{ROOT_DIR}:/workspace",
        "-e", f"TARGET_GRAPH_BUILD_ID={build_id}",
        "-e", f"TARGET_GRAPH_ID_MODULE_NAME={module_name}",
        image, "bash", "-c", c_script,
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    subprocess.run(["chmod", "-R", "a+rw", str(out_dir)], stderr=subprocess.DEVNULL)


def test_target_candidates(case_id: str, candidates: List[str], image: str = "target-graph:svf-llvm14", timeout: int = 120) -> Optional[str]:
    if not candidates:
        return None
    # Join with comma
    cand_str = ",".join(candidates)
    c_script = f"""
set -uo pipefail
out="/workspace/cases/{case_id}/svf_backend"
extapi="/opt/SVF/Release-build/svf-llvm/extapi.bc"
rm -f "$out/test_svfg.json"

targetgraph-svf \
  --input "$out/tagged.bc" \
  --extapi-bc "$extapi" \
  --target-inst "{cand_str}" \
  --max-nodes 100000 \
  --max-edges 300000 \
  --output "$out/test_svfg.json" 2> "$out/test.err" || true

if [ -s "$out/test_svfg.json" ]; then
  grep "Resolved target instruction:" "$out/test.err" || true
fi
"""
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{ROOT_DIR}:/workspace",
        image, "bash", "-c", c_script,
    ]
    try:
        proc = subprocess.run(cmd, timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Check stderr or stdout for Resolved target instruction
        for line in proc.stdout.splitlines() + proc.stderr.splitlines():
            if "Resolved target instruction:" in line:
                return line.split("Resolved target instruction:", 1)[1].strip()
        # Fallback: read test_svfg.json target field
        test_json = ROOT_DIR / "cases" / case_id / "svf_backend" / "test_svfg.json"
        if test_json.is_file() and test_json.stat().st_size > 0:
            data = json.loads(test_json.read_text(encoding="utf-8"))
            tgt = data.get("target")
            if tgt:
                return tgt
        return None
    except subprocess.TimeoutExpired:
        return None


def find_candidate_instructions(case_dir: Path, oracle: Dict[str, Any]) -> List[str]:
    bb_map_path = case_dir / "bb_map.jsonl"
    before_path = case_dir / "svf_backend" / "before.jsonl"
    
    o_func = oracle.get("function", "")
    o_file = oracle.get("relative_source_file", "") or oracle.get("file", "")
    o_file_base = os.path.basename(o_file)
    o_line = oracle.get("line")

    # Tokenize o_func (split by non-alphanumeric, filtering short tokens)
    func_tokens = [tok for tok in re.split(r'[^a-zA-Z0-9]', o_func) if len(tok) >= 3 and tok.lower() not in ('zzip', 'get', 'set')]

    # 1. Read bb_map
    # bb_id -> {function, lines: set(), files: set()}
    bb_info: Dict[str, Dict[str, Any]] = {}
    with open(bb_map_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip(): continue
            rec = json.loads(line)
            bb_id = rec.get("bb_id")
            fn = rec.get("function", "")
            dlocs = rec.get("debug_locations", [])
            lines = set()
            files = set()
            for d in dlocs:
                if d.get("line"): lines.add(d["line"])
                if d.get("file"): files.add(os.path.basename(d["file"]))
            bb_info[bb_id] = {
                "function": fn,
                "lines": lines,
                "files": files,
            }

    # 2. Read before.jsonl: bb_id -> list of instructions
    bb_insts: Dict[str, List[Dict[str, Any]]] = {}
    with open(before_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip(): continue
            rec = json.loads(line)
            bb_id = rec.get("bb_id")
            bb_insts.setdefault(bb_id, []).append(rec)

    # 3. Score BBs
    scored_bbs: List[Tuple[int, str]] = []
    for bb_id, info in bb_info.items():
        if bb_id not in bb_insts:
            continue
        score = 0
        fn = info["function"]
        # Function matching
        if o_func and fn == o_func:
            score += 100
        elif any(tok in fn for tok in func_tokens):
            score += 40
        
        # File matching
        if o_file_base and any(o_file_base in f for f in info["files"]):
            score += 30
            
        # Line matching
        if o_line and o_line in info["lines"]:
            score += 50
        elif o_line and any(abs(l - o_line) <= 3 for l in info["lines"]):
            score += 20

        if score >= 40:
            scored_bbs.append((score, bb_id))

    # If any BB has score >= 100 (exact function match), filter out BBs that didn't match function
    max_score = max((s for s, _ in scored_bbs), default=0)
    if max_score >= 100:
        scored_bbs = [(s, b) for s, b in scored_bbs if s >= 100]

    scored_bbs.sort(key=lambda x: x[0], reverse=True)

    # Preferred opcodes for memory / value flow
    OPCODE_WEIGHT = {
        "load": 10,
        "store": 9,
        "getelementptr": 8,
        "call": 7,
        "invoke": 6,
        "phi": 5,
        "select": 4,
        "bitcast": 3,
        "icmp": 2,
    }

    candidates = []
    for _, bb_id in scored_bbs[:8]:
        insts = bb_insts.get(bb_id, [])
        scored_insts = []
        for inst in insts:
            op = inst.get("opcode", "")
            w = OPCODE_WEIGHT.get(op, 1)
            scored_insts.append((w, inst.get("id")))
        scored_insts.sort(key=lambda x: x[0], reverse=True)
        for _, inst_id in scored_insts:
            if inst_id:
                candidates.append(inst_id)

    if not candidates:
        fallback_bbs = []
        for bb_id, insts in bb_insts.items():
            if not insts:
                continue
            fn = insts[0].get("function", "")
            common = sum(1 for tok in func_tokens if tok.lower() in fn.lower())
            if common > 0:
                fallback_bbs.append((common, bb_id))
        fallback_bbs.sort(key=lambda x: x[0], reverse=True)
        for _, bb_id in fallback_bbs[:5]:
            insts = bb_insts.get(bb_id, [])
            for inst in insts:
                if inst.get("opcode") in ("load", "store", "getelementptr", "call"):
                    candidates.append(inst["id"])

    return candidates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT_DIR / "configs/projects/benchmark_30_cases.yaml")
    parser.add_argument("--case", type=str, help="Calibrate single case")
    parser.add_argument("--apply", action="store_true", help="Apply updates directly to config YAML")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    cases = config.get("cases", [])
    if args.case:
        cases = [c for c in cases if c["case_id"] == args.case]

    print(f"Calibrating target instructions for {len(cases)} cases...")
    updates = {}

    for idx, c in enumerate(cases, 1):
        cid = c["case_id"]
        cdir = ROOT_DIR / "cases" / cid
        oracle = c.get("expected_oracle", {})
        old_target = c.get("canonical_target_inst")

        bc_files = list(cdir.glob("*.bc"))
        if len(bc_files) != 1:
            print(f"[{idx:02d}/{len(cases):02d}] {cid}: FAIL (found {len(bc_files)} bc files)")
            continue

        bc_name = bc_files[0].name
        try:
            build_id, mod_name = get_canonical_provenance(cdir, bc_name)
            ensure_tagged_bc(cid, cdir, bc_name, build_id, mod_name)
        except Exception as e:
            print(f"[{idx:02d}/{len(cases):02d}] {cid}: FAIL tagging ({e})")
            continue

        # Check if old_target is tagged in before.jsonl
        before_file = cdir / "svf_backend" / "before.jsonl"
        old_target_in_ir = False
        if old_target and before_file.is_file():
            with open(before_file, "r", encoding="utf-8") as bf:
                for bfl in bf:
                    if f'"{old_target}"' in bfl:
                        old_target_in_ir = True
                        break

        if old_target_in_ir and test_target_candidates(cid, [old_target]):
            print(f"[{idx:02d}/{len(cases):02d}] {cid}: OK (old target {old_target} still valid)")
            updates[cid] = old_target
            continue

        # Find candidate instructions
        candidates = find_candidate_instructions(cdir, oracle)
        print(f"[{idx:02d}/{len(cases):02d}] {cid}: Old target {old_target} invalid; testing {len(candidates)} candidates in 1 pass...")
        found = test_target_candidates(cid, candidates)

        if found:
            print(f"      -> SUCCESS: Calibrated to {found}")
            updates[cid] = found
        else:
            print(f"      -> FAILED to find valid SVFG target instruction!")

    print("\n" + "=" * 50)
    print(f"Calibration finished: {len(updates)}/{len(cases)} cases have valid SVFG targets.")

    if args.apply:
        for c in config["cases"]:
            cid = c["case_id"]
            if cid in updates:
                c["canonical_target_inst"] = updates[cid]
        with open(args.config, "w", encoding="utf-8") as f:
            yaml.dump(config, f, sort_keys=False, allow_unicode=True)
        print(f"Applied updates to {args.config}")


if __name__ == "__main__":
    main()

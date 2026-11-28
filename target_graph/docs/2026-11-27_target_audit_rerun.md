# 30-case rerun: fail-closed target identity and inline-aware diagnostics

Scope: fix the **11/30 PASSED** rerun's observed ASan path misclassification
and target identity/inline-owner ambiguity. No changes to native SVF's
value-flow semantics, BB trace runtime or the weak-positive set definition.

## New guarantees

- ASan paths are lexically normalized for `/./` and `/../`; sanitizer type,
  function, and source line **still match exactly**. In particular the
  binutils cxxfilt/nm `/./` false negatives can be distinguished from truly
  different fault sites. Do NOT loosen imageworsener, jhead or zziplib lines.
- The audit emits `target_diagnostics.json` for every case with trustworthy
  BC/PoC/trace hashes. It reports whether the configured instruction exists
  in the *current* original LLVM instruction map and BB graph, the complete
  set of exact matching oracle source-line BBs, whether each was executed by
  the Direct BB-ID trace, and owning LLVM functions. It **never substitutes**
  a different target automatically.
- Original `AnalysisV2Pass.cpp` emits `inline_callsite_chain` for instructions
  with an LLVM `DILocation::getInlinedAt()` chain. This enriches
  `candidate_instructions` if fresh `analysis_v2_nodes.jsonl` exists.
  It is explicitly not a crash-PC-to-IR mapping.
- The audit distinguishes `ASAN_TYPE_MISMATCH` from
  `ASAN_FRAME_MISMATCH`, `TARGET_NOT_IN_CURRENT_GRAPH`,
  `TARGET_NOT_IN_CURRENT_IR`, `TARGET_NOT_EXECUTED` and other stages.
- `calibrate_targets.py` uses only an ASan-verified, SHA-verified
  *direct BB* trace and exact oracle source-line owner candidates to
  generate `target_calibration.json`. A native SVFG-compatible candidate is
  a **proposal**, not proof of the faulting instruction.

## Fast first pass: audit existing artifacts WITHOUT rebuilding

```bash
git fetch origin
git switch refactor/target-graph-svf-backend
git pull --ff-only origin refactor/target-graph-svf-backend
cd target_graph

python3 scripts/audit_and_label.py
```

Inspect these files, especially for previously rejected cases:
`cases/<case-id>/audit.json`,
`cases/<case-id>/target_diagnostics.json`,
`reports/weak_labels_audit/audit_summary.json`.

Running the audit again clears a previous `svf_weak_labels.json` for any case
that now fails. **PASSED still means candidate weak-positive BBs only**;
unlisted BBs remain UNKNOWN, not ground-truth negatives.

Expected patterns (not promised new pass counts):
- binutils cxxfilt and nm: ASan path-normalization succeeds, but the
  original configured target BB did not exist in the archived graph.
- cJSON-1010239, zziplib-152/153, Bento4-336/14261,
  libming-7578/11728: source-line oracle BB(s) executed, but the
  originally configured static target BB was not. Review LLVM owning
  function and inlining rather than automatically substituting the
  first executed BB.
- imageworsener / jhead / zziplib-151: ASan frame mismatch remains
  unresolved pending independent DWARF/source/PoC verification.

## Refresh LLVM14 inline callsite metadata (targeted)

Do this only after Docker images are built with the new AnalysisV2Pass:

```bash
docker build -t target-graph:llvm14 \
  -f docker/llvm-build/Dockerfile .

# For a representative affected case:
bash scripts/graph_v2.sh --case cJSON-1.7.8_cJSON_CVE-2019-1010239

python3 scripts/audit_and_label.py \
  --case cJSON-1.7.8_cJSON_CVE-2019-1010239 \
  --output-dir reports/spotcheck_cjson
```

`graph_v2.sh` now uses the original `pass_summary.json` BuildID and ModuleName
for alias cases so the newly emitted V2 instruction IDs match original
graph IDs. Check `target_diagnostics.json`'s `inline_metadata_status`.
If the original optimized LLVM module has no inlining, an empty
`inline_callsite_chain` is expected.

## Propose targets, DO NOT auto-write config

Only after a **fresh** direct trace exists:

```bash
docker build -t target-graph:svf-llvm14 \
  -f docker/svf-llvm14/Dockerfile .

python3 scripts/calibrate_targets.py \
  --case cJSON-1.7.8_cJSON_CVE-2019-1010239
```

Read `cases/<id>/target_calibration.json`. The suggested instruction is
`svfg_compatible_proposal`. Review the original `.bc`, the ASM faulting
instruction/ASan PC, LLVM owning function, inlinedAt chain, operand and
the exact PoC before approving a different target. **SVFG compatibility
alone is never a reason to approve.**

`--apply` will reject operation without an explicit reviewed JSON file:

```json
{
  "cases": {
    "EXACT_CASE_ID": {
      "target_inst": "0123456789abcdef:3",
      "faulting_instruction_evidence":
        "ASan faulting PC, LLVM load/store operand and inlinedAt owner checked"
    }
  }
}
```

Save it to an untracked file and apply only after independent review:

```bash
python3 scripts/calibrate_targets.py \
  --case EXACT_CASE_ID \
  --apply \
  --approved-targets /path/to/approved_targets.json
```

All approvals are validated before any YAML modification; rejected or
ambiguous cases cannot partially rewrite the manifest. Commit approved
target changes separately for provenance.

## After reviewed calibration (selected cases first)

```bash
python3 scripts/evaluate_svf.py --case-id EXACT_CASE_ID --jobs 1
python3 scripts/audit_and_label.py \
  --case EXACT_CASE_ID --output-dir reports/spotcheck_after_calibration
```

When spot checks are correct, run:

```bash
python3 scripts/evaluate_svf.py --jobs 2
python3 scripts/audit_and_label.py
```

**No source rebuild is needed** for path-normalization or Audit logic only.
Rebuilding source bitcode invalidates old SVF/Trace hashes and requires a
full rebuild/materialization/retrace/SVF rerun, in the proper order.

For the next review, export the new `audit_summary.json` and relevant
`target_diagnostics.json` / `target_calibration.json`, along with the
pre-existing `svf_summary.json` if any SVF cases failed.

### Limitations

This audit still does NOT identify the faulting operand by native ASan PC.
Inline callsite metadata narrows ambiguous LLVM owners but cannot alone
prove causality. No automatic benchmark success-rate optimization, line
fuzzing, context-insensitive SVFG cutoff or verified negative BB labels
are introduced.


## 2026-11-27 21:51+08 audit follow-up: per-instruction candidate safety

The newly uploaded 30-case audit remains **11 PASSED / 19 FAILED**:
8 `ASAN_FRAME_MISMATCH` (imageworsener 4, jhead 3, zziplib-151 1),
7 `TARGET_BB_NOT_HIT_IN_DIRECT_TRACE`, and
4 `TARGET_NOT_IN_CURRENT_GRAPH`. ASan path normalization did work:
binutils cxxfilt/nm now match the ASan frame, but their previously
configured target IDs are not in the current LLVM graph.

A significant calibration pitfall has been fixed:
`bb_map.debug_locations` is the *union of instruction locations within
a BB*. A BB with source line 42 and 99 must **not** make every `load`
or `store` in that BB a line-42 fault-site candidate.

`inspect_target` now verifies each instruction against
`analysis_v2_nodes.jsonl` using its exact instruction ID, BB ID,
opcode, owning LLVM function, full source path, and source line.
`calibrate_targets.py` accepts only candidates with
`v2_instruction_identity_verified=true` and
`instruction_exact_oracle_source_line=true`, plus trusted direct BB
execution and a value-flow-relevant opcode. Missing/mismatched V2
metadata is a diagnostic blocker, not permission to guess.

This remains only *source-location filtering*, **not** an ASan
fault-PC/LLVM operand proof. A manual approval is still required.

Rebuild Analysis V2 metadata **only** for the 11 target-failing cases
after rebuilding the LLVM14 image with the current commit. For the
8 ASan frame mismatch cases, first investigate version/DWARF/stack
rather than rerunning SVF.

The audit also records non-top ASan frame depth and high
weak-positive/trace retention as warnings without changing PASSED.
Non-top matching frames are useful oracle evidence but are not
a verified faulting instruction location.

### Suggested minimal commands

```bash
cd target_graph
git pull --ff-only origin refactor/target-graph-svf-backend

# No Docker or SVF rebuild necessary for updated audit diagnostics:
python3 scripts/audit_and_label.py

# After rebuilding target-graph:llvm14, refresh a problematic case's V2:
bash scripts/graph_v2.sh --case bento4-1.5.0_mp42aac_ASARUBBO-336
python3 scripts/audit_and_label.py \
  --case bento4-1.5.0_mp42aac_ASARUBBO-336 \
  --output-dir reports/spotcheck_bento4_336

# Native SVFG proposals are optional and expensive. If ready:
python3 scripts/calibrate_targets.py \
  --case bento4-1.5.0_mp42aac_ASARUBBO-336
```

Compare `target_diagnostics.json` and `target_calibration.json`.
Do NOT use `--apply` without reviewed independent crash-PC/operand
evidence. No automatic target changes were made by this code review.


## 2026-11-27 21:58+08 — Bento4 ASARUBBO-336 candidate audit

Uploaded outputs:

- The **30-case** audit remains 11/30 (8 ASAN_FRAME_MISMATCH,
  7 TARGET_BB_NOT_HIT_IN_DIRECT_TRACE, 4 TARGET_NOT_IN_CURRENT_GRAPH).
- The separate **one-case** audit for Bento4-336 is 0/1 because the
  currently configured target `b06991cc1ff4d469:1` belongs to
  `AP4_ProtectedSampleDescription::ToAtom` and was not executed.
- The executed oracle BB `002d55dafb123847` belongs to
  `AP4_AtomFactory::CreateAtomFromStream`. Its per-instruction DebugLoc
  is `Ap4Atom.h:247` with `inlinedAt=Ap4AtomFactory.cpp:499`.
  Both `002d55dafb123847:5` (`getelementptr`) and
  `002d55dafb123847:6` (`store`) meet the strict DebugLoc + direct-BB
  conditions.
- The prior `svfg_compatible_proposal=:5` only means the native SVF
  backend selected the first candidate with a mapped value-flow node.
  It DOES NOT establish that the GEP itself is the faulting memory
  operation. The actual setter's `store` is a stronger *faulting-write
  candidate*, but this is NOT yet confirmed by the crash PC/operand.

### Candidate probe fixes

`targetgraph-svf` now emits `candidate_seed_counts` for **all**
requested candidate instructions from one native SVFG construction.

`calibrate_targets.py` now:
1. Removes old probe outputs and does **not** swallow nonzero native
   exit codes or accept resolved-target log messages as success.
2. Requires a completed `EXPLORATORY_ONLY` report with matching target,
   candidate ordering, nonzero selected seeds and valid mapped nodes.
3. Saves `svfg_candidate_probe` with each candidate's seed count,
   `candidate_instruction_evidence` with opcode/inline provenance, and
   `direct_memory_access_alternatives` when the first mapped seed is only
   address computation.
4. Never automatically changes the benchmark Oracle or LLVM target.
   `--apply` still needs explicit, reviewed fault-site evidence.

**This change requires rebuilding only the SVF Docker image; no source,
Bitcode, PoC, or Direct BB Trace rebuild is needed.**

```bash
cd target_graph
git fetch origin
git switch refactor/target-graph-svf-backend
git pull --ff-only origin refactor/target-graph-svf-backend

docker build -t target-graph:svf-llvm14 \
  -f docker/svf-llvm14/Dockerfile .

python3 scripts/calibrate_targets.py \
  --case bento4-1.5.0_mp42aac_ASARUBBO-336
```

Inspect `cases/bento4-1.5.0_mp42aac_ASARUBBO-336/target_calibration.json`:
`svfg_candidate_probe.candidate_seed_counts` should contain both
`:5` and `:6`; each has an independently reported number of SVFG
nodes. If the native analysis exceeds the budget or fails, it must show
`SVFG_PROBE_INCOMPLETE` and preserve the reason — no stale proposal.

Even if `:6` has SVFG seeds, confirm its store pointer corresponds to
`AP4_Atom::SetType`'s field write and the ASan fault PC. A BB-entry
trace proves BB execution, not that every instruction in the BB completed.
Do not automatically approve either seed or label the remaining BBs negative.

For next review, provide the fresh `target_calibration.json` and, if
probe fails, `svf_backend/test.err` plus native exit code. Do not rerun
all 30 cases solely to compare these two candidates.


### Bento4-336: confirmation of both native SVFG seed counts

The next user-run `target_calibration.json` confirms that BOTH executed,
exact-DebugLoc candidates in `002d55dafb123847` map to one SVFG seed:

| Instruction | LLVM opcode | Native SVFG seeds | Role |
| --- | --- | ---: | --- |
| `002d55dafb123847:5` | `getelementptr` | 1 | address calculation |
| `002d55dafb123847:6` | `store` | 1 | memory write |

The initial `svfg_compatible_proposal=:5` is an input-order selection:
**the SVFG does not prefer :5 over :6**. New
`faulting_access_review.memory_access_review_candidates` lists the
seeded memory operations first and sets
`single_memory_access_hypothesis=:6` for this case, while requiring
fault-PC/operand verification. This is a REVIEW HYPOTHESIS only.

A dereference at a `store` is consistent with
`AP4_Atom::SetType()` / `m_Type = type` and a SEGV, but the ASan-instrumented
faulting PC must still be correlated to the store's address operand.
A matching BB-entry trace cannot prove the in-BB store completed.
Furthermore, an SVFG seed at a store does not automatically certify
that backward traversal follows the **destination pointer** rather than
the stored value. Do not auto-apply the target or treat SVFG membership
as vulnerability ground truth.

After pulling the Python-only code changes (no Docker image rebuild needed):

```bash
cd target_graph
python3 scripts/calibrate_targets.py \
  --case bento4-1.5.0_mp42aac_ASARUBBO-336
```

Inspect `faulting_access_review` alongside the existing
`svfg_candidate_probe`; if fault-pointer provenance is confirmed,
apply a reviewed target via the existing `--approved-targets` protocol,
then rerun SVF and Audit for this **one case**.


### Read-only ASan PC + original LLVM-IR evidence collection

For Bento4-336, the ASan report now provides an exact faulting
PC `0x552da2`, WRITE access and address `0x8`. Native SVFG reports
one seed for `002d55dafb123847:5` (`getelementptr`) and
`002d55dafb123847:6` (`store`).

The canonical inspector is **`scripts/review_fault_pc.py`**. It
checks instrumented-binary, original-bitcode and crash-stderr SHA-256
against the saved run before collecting evidence. It does not
change the benchmark target, graph, or weak labels.

```bash
cd target_graph
python3 scripts/review_fault_pc.py \
  --case bento4-1.5.0_mp42aac_ASARUBBO-336
```

Output:
`cases/bento4-1.5.0_mp42aac_ASARUBBO-336/fault_pc_review.json`.

Check `machine_instruction_at_fault_pc` for exact x86-64 instruction
at `0x552da2`, `candidate_original_llvm_ir` for the original tagged
GEP/store IR, and provenance hashes. `objdump` and `llvm-dis-14` are
required to collect both parts (if missing, the output explicitly
states the incomplete extraction).

**Do not equate the instrumented binary PC with an original LLVM
instruction ID automatically:** ASan adds checks, and code generation
can change instruction boundaries and register allocation. Even a
machine WRITE to address `0x8` is only evidence of a near-null
dereference, not proof of the exact source operand's provenance.
After inspecting this output, review the store pointer operand
and decide whether `:6` is sufficiently corroborated for an
explicit, recorded manual approval.

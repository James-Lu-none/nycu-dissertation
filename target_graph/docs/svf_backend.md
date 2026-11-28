# SVF-2.9 / LLVM14 backend (Phase 1)

**Status:** independent, exploratory SVFG-based value-flow extractor. Do not
replace the full graph, DG baseline, dynamic PoC trace or training labels.
Implementation is based on the existing DG sidecar branch
`refactor/target-graph-dg-backend` and uses its *identity-only* LLVM pass.

## Why SVF and why version 2.9?

The preliminary DG evaluation succeeded in 2/30 cases, with 10 timeouts,
7 segfaults, 1 abort, 9 original-target-ID failures and 1 survivor mismatch.
Those results are NOT evidence that SVF is faster or more accurate. In
particular, target-ID failures need fixing regardless of analysis backend.

SVF's upstream `SVF-2.9` release (commit
`0e56bc038bf207a1ca320b5f5ad241e13ab33e14`) officially targets LLVM
14. This avoids changing the original WLLVM / LLVM14 compilation pipeline.

SVF is distributed under the GNU AGPL license. Review licensing obligations
before distributing linked binaries or derivative implementations.

## Architecture

```text
Original WLLVM whole-program BC (*.bc) — never rewrite original
    |
    +-- Existing LLVM API graph/BB mapping, PoC trace [unchanged]
    |
    +-- LLVM DGIdentityPass (identity tagging ONLY)
            tagged.bc + before.jsonl (original BB:instruction IDs)
            |
            +-- Python preflight validates selected target and build IDs
            |
            +-- Native SVF-2.9 analysis (C++ linked to SvfLLVM)
                   SVFIRBuilder
                    -> AndersenWaveDiff
                    -> SVFGBuilder::buildFullSVFG
                    -> reverse traversal on incoming native SVFG edges
                        from ALL SVFG nodes mapped to target instruction
                    -> svfg_raw.json (full SVFG node/edge evidence)
            |
            +-- Python fail-closed validation of native SVFG graph
                  -> svf_slice.json (EXPLORATORY_ONLY)
```

**Exact scope:** SVFG backward **value flow**, NOT full program dependence
slicing, not complete control dependence, and not a call-context-precise
interprocedural SDG. Phi/memory summary nodes may be unmapped to any single
original LLVM instruction. The raw graph retains their SVFG identities;
`svf_slice.json` projects only nodes with explicit original LLVM identities.
Missing nodes, candidate faults and unresolved memory must NOT become
negative vulnerability labels.

### Original graph identity / relocated cases

**Important for ASARUBBO aliases and repeated CVEs:** the existing
`TargetGraphPass` derives each BB ID as SHA256 of
`build_id:module_name:function:BB_ordinal`, where the complete module path
is significant. Directory aliases are not safe hashing inputs.

`scripts/svf_slice.sh` now reads **both** `build_id` and `module_name`
from the original `pass_summary.json`, and supplies these to the
identity-only LLVM pass. It does not rename or alter the LLVM module.
Before launching Andersen, `preflight` verifies the complete original
instruction-ID set against `analysis_v2_nodes.jsonl` and the legacy
`bb_map.jsonl`. Existing function/opcode fields are also compared.

This change addresses the confirmed imageworsener and Bento4 cases where
`before.jsonl` from an alias build had no IDs in common with v2, even
though *all* instruction opcodes and owning functions matched by traversal
order. The exact security semantics of separately compiled binaries
still require independent bitcode provenance / PoC review.

**Use the canonical target instruction ID from analysis-v2, not the
former alias-hashed ID.** For the two archived diagnostic examples:

| Case | Alias-hashed target (incorrect for old graph) | Canonical v2 target |
| --- | --- | --- |
| imageworsener ASARUBBO-282 | `ccded5213c5b9424:3` | `72a7e069d71abdd7:3` |
| Bento4 CVE-2017-14261 | `1c9c3b95b14d42ec:6` | `055a12017da77749:6` |

The canonical IDs above came from strict same-ordinal function/opcode
matching over the archived samples. Reconfirm each target's source
location and PoC evidence before using it as a criterion.

**A separate issue:** the earlier 30-case evaluator reported
`PREFLIGHT_TARGET_NOT_TAGGED` for libxml2 even though the archived
`before.jsonl` contains that exact target and matches all 272,785 v2
instruction IDs. The archive also includes native-SVF log files created
around 120 seconds before the summary, consistent with a potential SVF
timeout. This is **not yet a verified timeout diagnosis**: preserve
subprocess exit code, stage and stderr when revising the batch runner;
never classify every nonzero exit as a preflight identity mismatch.

The SVF adapter uses the original `target_graph.dg.inst_id` LLVM metadata
written by the existing identity pass. This is an identity bridge, **not**
the DG dependence engine. Original BB identifiers are retained without
re-numbering from transformed SVF graph nodes.

## Build

```bash
cd target_graph

docker build -t target-graph:llvm14 \
  -f docker/llvm-build/Dockerfile .

docker build -t target-graph:svf-llvm14 \
  -f docker/svf-llvm14/Dockerfile .
```

The second build compiles upstream SVF-2.9, its matching `extapi.bc` external-function model, and the C++ adapter using LLVM14/Z3. It intentionally does NOT download a modern SVF master.

## One case

Use the original `scripts/build.sh` to create the case's whole-program bitcode.
Do not silently recompile another `.bc` with different flags.

Inspect candidates first:

```bash
bash scripts/graph.sh --case CASE_ID
bash scripts/graph_v2.sh --case CASE_ID
PYTHONPATH=src python -m target_graph.analysis_v2.cli \
  --case-dir cases/CASE_ID --target-bb BB_ID --list-targets
```

Review the source/inline owning function and PoC evidence. Exact instruction
IDs are of the form `0123456789abcdef:ordinal`. A fault source line alone is
insufficient when multiple inlined instructions share the location.

```bash
bash scripts/svf_slice.sh \
  --case CASE_ID \
  --target-inst 'SELECTED_ORIGINAL_BB:INSTRUCTION_ORDINAL' \
  --timeout-sec 120 \
  --max-nodes 100000 \
  --max-edges 300000

PYTHONPATH=src python -m target_graph.svf.compare \
  --case-dir cases/CASE_ID \
  --target-inst 'SELECTED_ORIGINAL_BB:INSTRUCTION_ORDINAL'
```

```text
cases/CASE_ID/svf_backend/
  tagged.bc        # original IR + identity metadata; original .bc unchanged
  before.jsonl      # original LLVM instruction -> original BB
  svfg_raw.json     # native SVFG node IDs, edge kinds, mapped/unmapped nodes
  svf.stdout.log
  svf.stderr.log
  svf_slice.json    # projection to original instructions/BBs; exploratory
```

When the target is absent from `before.jsonl`, the script fails BEFORE
expensive pointer analysis. This explicitly addresses the 9/30 DG validation
failures from the preliminary report. The folder stays separate from
`dg_backend/` and the existing `parquet/` bundle; a completed
`svf_slice.json` is never silently overwritten.

The C++ extractor has bounded visited-node and edge counts. The process
also has a wall-clock timeout; a timeout, crash, ambiguous identity or
incomplete report leaves no validated `svf_slice.json`.

## Tests

```bash
PYTHONPATH=src python -m pytest tests/unit/test_svf_validate.py -q
bash -n scripts/svf_slice.sh
```

See `.github/workflows/target-graph-svf.yml` for native LLVM14 + SVF
build and a small compiled C sample. The true success criterion is
completion on real WLLVM bitcode, not merely the toy test.

## Evaluation gate before 300-case rollout

Start with a stratified subset from the existing 30 cases:

- Two successful cJSON cases for the identity/label sanity check.
- Cases with previously stale target IDs; ensure preflight correctly rejects.
- Large binutils/libtiff cases, measure time and peak RSS.
- C++ Bento4 and problematic libming cases; distinguish parser/analysis crash.
- Trace/inlining-ambiguous libming: do not claim target certainty.

For each case record: SVF build/analysis status, timeout, peak memory,
original & mapped instructions, unmapped SVFG nodes, SVFG edges, target
seed count, original BB coverage and comparison to v2.

A low Jaccard between v2 and SVF does not prove either is wrong:
they compute different dependency relations. SVF backward value-flow
**must not be advertised as a full control/data backward slice**.

## Next, only if Phase 1 succeeds

1. Add *control dependence* via LLVM/DG or equivalent PDG analysis,
   explicitly retaining edge provenance.
2. Handle call/return matching if context sensitivity is needed, rather
   than claiming a context-sensitive result from raw reverse SVFG.
3. Validate a target-specific criterion with PoC evidence.
4. Add supervision conversion only after per-case acceptance tests. Do
   not auto-promote `EXPLORATORY_ONLY` to a trainable weak label.

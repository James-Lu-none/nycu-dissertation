# Analysis v2 — instruction-level value flow (phase 1)

**Status: experimental / partial.** This is a new analysis core. It does not modify
legacy `TargetGraphPass`, the ten benchmark builds, `bb_map.jsonl`,
`edges.parquet`, or existing trace/embedding data.

## What is implemented

- LLVM 14 module pass `analysis-v2` extracts **instruction-level** SSA
  def-use edges, including definitions and uses inside the *same basic block*.
- Each formal parameter is a distinct node; `PARAM_IN` links the **specific
  actual argument value** to the matching formal parameter with
  `callsite_id` and `arg_index` for **resolved direct calls**.
- A non-void call has a separate `call_result` node. Only a callee's
  return instruction binds to that value (`RET_BIND`); all other actual
  arguments are **not** connected to the return by default.
- Postdominator-derived `CONTROL` edges enter a BB control gate.
  `GUARD` edges go from that gate to individual instructions, so following
  one target instruction does **not** pull in unrelated sibling instructions.
- The Python slicer matches nested `RET_BIND` / `PARAM_IN` callsites using
  a bounded stack. Starting inside a callee with *no caller context* still
  legitimately considers multiple callers.
- Unknown memory sources, external and indirect calls are **explicit
  unresolved boundaries**. They do not become invented value-flow edges.
- Every witness path contains relation, callsite and argument index evidence.
- The original LLVM BB hashing scheme and `bb_map.jsonl` are checked for
  compatibility. The v2 graph refuses to mix old/new bitcode identities.

## What is NOT implemented or validated

- **MemorySSA/SVF reaching definitions**, alias-precise memory dependencies,
  interprocedural memory summaries, heap allocation provenance.
- Complete context-sensitive SDG/HRB two-phase slicing, recursion-safe
  precise context matching, and indirect-call pointer-target resolution.
- Provenance-certified fault operands, verified negatives, calibrated nnPU
  assumptions, or target supervision.
- This phase makes no claim to beat DG, SVF or DAFL. Benchmarks must be
  reproduced on the workstation with recorded tool versions and bitcode hashes.

A `verified` **SSA** edge means a verified LLVM operand binding, **not** a
verified vulnerability-triggering cause. It is invalid to use this tool's
graph as `SUPERVISION_VALIDATED` data.

## Run

The existing LLVM14 image must be **rebuilt** to contain the new pass:

```bash
cd nycu-dissertation/target_graph
docker build -t target-graph:llvm14 -f docker/llvm-build/Dockerfile .
PYTHONPATH=src python -m pytest tests/unit/test_analysis_v2_slicing.py -q
ANALYSIS_V2_DOCKER=1 PYTHONPATH=src \
  python -m pytest tests/integration/test_analysis_v2_llvm.py -q
```

Extract a single case (read-only to existing Parquet and traces):

```bash
bash scripts/graph_v2.sh --case libming-4.7.1_swftophp_CVE-2017-7578
```

Use the exact fault BB obtained from `reports/label_yield_audit.csv`.
**List** the candidate fault instructions first:

```bash
PYTHONPATH=src python -m target_graph.analysis_v2.cli \
  --case-dir cases/libming-4.7.1_swftophp_CVE-2017-7578 \
  --target-bb '<fault_bb_id>' --list-targets
```

After verifying the particular `store` or `load` instruction (do not
blindly choose the first line/BB match), run:

```bash
PYTHONPATH=src python -m target_graph.analysis_v2.cli \
  --case-dir cases/libming-4.7.1_swftophp_CVE-2017-7578 \
  --target-inst '<instruction_id>' \
  --output reports/libming_v2_slice.json
```

**Expected output:** `analysis_v2_nodes.jsonl`,
`analysis_v2_edges.jsonl`, `analysis_v2_summary.json`, and a
slice JSON containing representative paths, edge witness, unknown boundaries
and `validated_for_supervision: false`.

## Source-level inlining and fault-target ambiguity

**libming (observed 2026-11-20):** the LLVM14 module contains no explicit
direct call to the out-of-line `parseSWF_RGBA`, but `parser.c:68` `store`
appears **17 times across 12 owning IR functions**. At `-O1` the source
function is inlined into several callers. The previous source-location
mapping selected the uncalled out-of-line BB, so its 15-node slice is not
yet evidence for the particular PoC crash instruction.

List **all** line-68 stores instead of selecting the out-of-line BB:

```bash
PYTHONPATH=src python -m target_graph.analysis_v2.cli \
  --case-dir cases/libming-4.7.1_swftophp_CVE-2017-7578 \
  --source-file parser.c --line 68 --opcode store --list-targets
```

A list of candidates is NOT evidence that any particular instruction executed.
You need the instrumented binary's PoC execution trace, source debug inline
stack, and build provenance to identify which owning function(s) actually
executed. Sanitizer source-file/function matching is not equivalent to
exact IR instruction identity. If several instructions in one owner have the
same source location, the result must remain ambiguous until stronger
instrumentation or disassembly evidence is supplied.

The slicer now labels a formal without incoming `PARAM_IN` as
`UNBOUND_FORMAL`, instead of silently treating it as a complete source.
This can mean inlining, an indirect caller, an entrypoint or incomplete
bitcode; it is NOT proof that the function is unreachable.

## Phase 2 acceptance criteria

1. `libming`: identify the fault **store pointer**, resolve its formal
   parameter to a specific direct caller actual value; unresolved memory
   or indirect call paths must remain `unknown`.
2. `libxml2`: trace `content->c2` with separate pointer-load and memory
   provenance; do not claim the original allocation without memory evidence.
3. `libtiff`: require valid MemorySSA clobber evidence; never connect a
   later store to an earlier load solely by aliasing.
4. Integrate MemorySSA with `MemoryDef/MemoryUse/MemoryPhi` and accurate
   `liveOnEntry` / unresolved-source tracking. Prefer SVF for selected
   interprocedural memory-flow paths.
5. Only after manual + dynamic verification define an explicit mapping from
   value-flow criteria to BB-level target scores. Preserve the old
   `target_graph` as a baseline.

The v2 core remains separate from `training/datasets.py`; formal training
must continue to fail closed on unverified labels.

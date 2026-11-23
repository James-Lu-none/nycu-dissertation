# DG backend migration — phase 1

Base commit: `a996f722f7c34141b9adbf90d1b901e5a2daceb4`.

**Status:** new non-destructive DG sidecar; LLVM/DG Docker integration still
requires workstation verification. This change does not overwrite legacy
Parquet graphs, PoC traces, existing embeddings, or training labels.

## Division of responsibility

| Component | Responsibility |
| --- | --- |
| WLLVM + pinned LLVM 14 | Existing whole-program bitcode builds |
| LLVM API / existing passes | Original BB IDs, full graph, candidate fault instructions |
| **DG `llvm-slicer`** | Static pointer/data/control dependence, backward slicing |
| New `DGIdentityPass` | Tag original instruction identities and export survivors |
| New `target_graph.dg` | Validate build/ID consistency, export exploratory slice |
| Existing PoC trace / label audit | Dynamic execution evidence, preserved unchanged |

DG is the **slicing backend** in phase 1, *not* yet the full DDG/CDG
edge exporter. Replacing the existing approximate graph-edge extraction
requires a separate evidence-preserving integration.

The **same original bitcode** must feed current graph passes and DG.
Instruction identities are tagged before slicing. BB IDs must **not** be
recomputed from the changed CFG of sliced bitcode, which can change node
ordinal positions and invalidate trace alignment.

## Build

DG is pinned at `dc3615d03fedfce62f37604b45d22e31c9d7e557`
(2025-05-21). The LLVM base image already includes WLLVM.

```bash
cd target_graph
docker build -t target-graph:llvm14 -f docker/llvm-build/Dockerfile .
docker build -t target-graph:dg-llvm14 -f docker/dg-llvm14/Dockerfile .
docker run --rm target-graph:dg-llvm14 llvm-slicer -version
```

This exact Docker combination is **not yet validated on the workstation**.
Any DG/LLVM API compatibility issue should be resolved and recorded before
changing analysis semantics or training labels.

## Run on an existing case

First generate the original graph and its instruction mapping from the
existing WLLVM bitcode, using the original case/build ID.

```bash
bash scripts/graph.sh --case CASE_ID
bash scripts/graph_v2.sh --case CASE_ID

PYTHONPATH=src python -m target_graph.analysis_v2.cli \
  --case-dir cases/CASE_ID \
  --source-file parser.c --line 68 --opcode store --list-targets
```

Review all candidate LLVM instruction owners against PoC evidence.
Inlined instructions can share a source line; choosing the first
candidate would not prove a fault-site identity.

Run DG with an explicit candidate instruction ID and *separately* specified
DG slicing criterion:

```bash
bash scripts/dg_slice.sh \
  --case CASE_ID \
  --target-inst '<bb_id>:<instruction_ordinal>' \
  --criterion 'actual_sink_or_line:variable' \
  --criterion-mode c
```

The optional `--criterion-mode sc` accepts DG's
`file#function#line#obj` syntax; `--entry FUNCTION` changes DG's
default entry from `main`. In both modes, matching is potentially
approximate. See
[DG's upstream slicing docs](https://github.com/mchalupa/dg/blob/dc3615d03fedfce62f37604b45d22e31c9d7e557/doc/llvm-slicer.md).

The wrapper requires exactly one original `.bc` in the case root. It
checks IDs against `bb_map.jsonl` and `analysis_v2_nodes.jsonl` if
present, and refuses to overwrite an existing output.

```text
cases/CASE_ID/dg_backend/
  tagged.bc          # original bitcode with identity metadata
  before.jsonl        # original instruction -> original BB
  sliced.bc           # DG output; not used for BB renumbering
  after.jsonl         # DG survivors with retained original IDs
  dg.stdout.log
  dg.stderr.log
  dg_slice.json       # EXPLORATORY_ONLY, NOT training-ready
```

**Unresolved:** Retention of a target instruction does not prove the
criterion matched exactly that instruction. DG may select multiple
callsites or source locations. It may also generate new untagged
instructions, which the adapter intentionally excludes. If the selected
target has no surviving original identity, validation fails closed.

## Compare with the existing analysis-v2

```bash
PYTHONPATH=src python -m target_graph.dg.compare \
  --case-dir cases/CASE_ID \
  --target-inst '<bb_id>:<instruction_ordinal>' \
  --output cases/CASE_ID/dg_backend/compare_v2.json
```

Jaccard, DG-only BBs and v2-only BBs are diagnostics; disagreement is not
proof of a bug in either implementation. In particular, v2 has known
unresolved memory provenance and direct-call limitations.

## Tests

```bash
PYTHONPATH=src pytest tests/unit/test_dg_validate.py -q

# Only after the Docker images build successfully:
DG_LLVM14_DOCKER=1 PYTHONPATH=src \
  pytest tests/integration/test_dg_llvm.py -q
```

Before using DG data as Stage 2 supervision, manually audit at least
5–10 real PoCs: bitcode/build provenance, precise inlined fault owners,
DG criterion matches, operand/memory dependency evidence, and trace
alignment. Include vulnerable/patched pairs; do not turn slice-excluded
nodes into negatives. `validated_for_supervision` and
`criterion_verified` intentionally remain `false`.

The original `run_all.sh`, `graph.sh`, `graph_v2.sh`,
`TargetGraphPass`, `AnalysisV2Pass`, and training remain unchanged.

## Next phase

Export **actual DG DDG/CDG instruction edges** with native DG evidence
instead of inferring more dependencies in Python/LLVM. Project these
onto original BB IDs, preserve analysis provenance and unresolved cases,
then conduct edge-level regression comparisons before switching the
default Stage 1 graph backend.

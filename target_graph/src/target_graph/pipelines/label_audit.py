"""Label-Yield Audit pipeline for target-conditioned program graph learning."""
from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
import pandas as pd

from target_graph.graphs.validate import validate_graph_bundle
from target_graph.labels.slicing import (
    compute_slicing_ablation,
    partition_target_candidates,
    trace_backward_slice_diagnostics,
)
from target_graph.llvm.mapping import BasicBlockMapper
from target_graph.tracing.sanitizer import parse_sanitizer_output
from target_graph.tracing.symbolizer import trace_to_basic_blocks


@dataclass
class CaseAuditRecord:
    case_id: str
    project: str
    cve: str
    target_binary: str
    vulnerable_version: str
    fixed_commit: str
    expected_sanitizer: str
    expected_function: str
    expected_file: str
    expected_line: int
    observed_sanitizer: str
    observed_function: str
    observed_file: str
    observed_line: int
    oracle_reproduced: bool
    target_bb: str
    fault_bb_in_trace: bool
    fault_bb_in_dep_slice: bool
    analysis_incomplete: bool
    slice_quality: str
    supervision_suitability: str
    missing_fault_operands: bool
    fault_operand_coverage: Optional[float]
    quality_rationale: str
    num_nodes_V: int
    num_edges: int
    num_executed_Et: int
    num_slice_dep: int
    num_slice_interproc: int
    num_slice_legacy: int
    num_reachable_exec: int
    num_weak_positives_dep: int
    num_weak_positives_interproc: int
    num_weak_positives_legacy: int
    retention_dep: float
    retention_interproc: float
    retention_legacy: float
    trace_coverage: float
    slice_coverage: float
    positive_yield: int
    num_slice_St: int
    num_reachability_Rt: int
    num_weak_positives_Pt: int
    num_unknown_unexecuted_Ut: int
    num_executed_non_slice_Ct: int
    num_verified_negatives_Nt: int
    has_verified_negatives: bool
    training_recommendation: str


def audit_case(
    case_cfg: Dict[str, Any],
    cases_root: Path,
    return_context: bool = False,
) -> CaseAuditRecord | Tuple[CaseAuditRecord, Dict[str, Any], Dict[str, Any]]:
    case_id = case_cfg["case_id"]
    case_dir = cases_root / case_id
    parquet_dir = case_dir / "parquet"

    # Validate parquet graph bundle first
    validate_graph_bundle(parquet_dir)

    # 1. Parse sanitizer stderr
    stderr_file = case_dir / "crash_stderr.txt"
    stderr_text = stderr_file.read_text(encoding="utf-8", errors="replace")
    san_report = parse_sanitizer_output(stderr_text)
    if not san_report:
        raise ValueError(f"Failed to parse sanitizer report from {stderr_file}")

    exp_oracle = case_cfg["expected_oracle"]
    exp_file_base = Path(exp_oracle["file"]).name

    # Search call stack for target frame matching the expected vulnerable location
    target_frame = None
    for f in san_report.frames:
        if (
            exp_oracle["function"].lower() in f.function_name.lower()
            or f.function_name.lower() in exp_oracle["function"].lower()
        ) and Path(f.source_file).name == exp_file_base:
            target_frame = f
            break

    if target_frame is None:
        target_frame = san_report.crash_frame

    obs_fn = target_frame.function_name if target_frame else "unknown"
    obs_file = target_frame.source_file if target_frame else "unknown"
    obs_line = target_frame.line_number if target_frame else 0
    obs_file_base = Path(obs_file).name if obs_file else ""

    oracle_reproduced = (
        san_report.error_type.lower() == exp_oracle["sanitizer"].lower()
        and (exp_oracle["function"].lower() in obs_fn.lower() or obs_fn.lower() in exp_oracle["function"].lower())
        and obs_file_base == exp_file_base
        and abs(obs_line - exp_oracle["line"]) <= 5  # Allow minor line offset due to comments
    )

    # 2. Map target BB
    mapper = BasicBlockMapper(case_dir / "bb_map.jsonl")
    target_bbs = mapper.map_source_location(obs_file, obs_line, function_name=obs_fn)
    if not target_bbs and obs_fn != exp_oracle["function"]:
        target_bbs = mapper.map_source_location(obs_file, obs_line, function_name=exp_oracle["function"])
    if not target_bbs:
        target_bbs = mapper.map_source_location(obs_file, obs_line)
    if not target_bbs:
        # Fallback using base filename
        target_bbs = mapper.map_source_location(exp_file_base, exp_oracle["line"], function_name=exp_oracle["function"])
    if not target_bbs:
        target_bbs = mapper.map_source_location(exp_file_base, exp_oracle["line"])
    if not target_bbs:
        raise ValueError(f"Could not map crash site {obs_file}:{obs_line} to any basic block in {case_id}")
    target_bb = target_bbs[0]

    # 3. Symbolize trace
    nodes_df = pd.read_parquet(parquet_dir / "nodes.parquet")
    edges_df = pd.read_parquet(parquet_dir / "edges.parquet")

    # Locate instrumented binary
    inst_binary = None
    for cand in case_dir.glob("*_inst"):
        inst_binary = cand
        break
    if not inst_binary:
        raise FileNotFoundError(f"No *_inst binary found in {case_dir}")

    trace_file = case_dir / "trace_crash.txt"
    executed_bbs = trace_to_basic_blocks(
        trace_file=trace_file,
        binary_path=inst_binary,
        bb_mapper=mapper,
    )

    # 4. Partition candidates
    all_bbs = set(nodes_df["bb_id"].unique())
    partition = partition_target_candidates(
        all_bbs=all_bbs,
        executed_trace_bbs=executed_bbs,
        edges_df=edges_df,
        target_bb=target_bb,
    )

    # 5. Fault BB verification & non-zero positive yield validation (P0 item 3)
    fault_bb_in_trace = target_bb in partition.E_t
    if not fault_bb_in_trace:
        raise RuntimeError(
            f"Sanitizer fault BB '{target_bb}' ({obs_file}:{obs_line}) was NOT recorded in trace for case {case_id}! "
            f"Trace executed {len(partition.E_t)} basic blocks. Disallowing silent pass."
        )

    if len(partition.P_t) == 0:
        raise RuntimeError(
            f"Weak positive yield |P_t| == 0 for case {case_id}! "
            f"Target BB: {target_bb}, |E_t|={len(partition.E_t)}, |S_t|={len(partition.S_t)}. "
            "Disallowing silent pass (libjpeg P_t=0 guard)."
        )

    if partition.supervision_suitability == "REJECT_UNVERIFIED_PROVENANCE":
        rec = "reject_unverified_provenance"
    elif partition.supervision_suitability == "REJECT_DEGENERATE_TARGET_ONLY":
        rec = "reject_supervision_degenerate_target_only"
    elif partition.supervision_suitability == "REJECT_INCOMPLETE_DEPENDENCY":
        rec = "reject_supervision_missing_caller_operands"
    elif partition.supervision_suitability == "FILTER_REQUIRED_MUST_MEM_OR_CDG":
        rec = "caution_over_inclusive_filter_may_alias"
    elif partition.supervision_suitability == "ACCEPT_LOCAL_ONLY":
        rec = "accept_local_supervision_with_pu_learning"
    elif partition.supervision_suitability == "ACCEPT_AS_SUPERVISION":
        rec = "accept_target_supervision_with_pu_learning"
    elif partition.has_verified_negatives:
        rec = "pairwise_ranking_with_verified_negatives"
    else:
        rec = "skip_pairwise_ranking_use_pu_learning"

    num_V = len(partition.V)
    num_Et = len(partition.E_t)
    num_St_dep = len(partition.S_dep)
    num_St_interproc = len(partition.S_interproc)
    num_St_legacy = len(partition.S_legacy)
    num_Rt_exec = len(partition.R_exec)
    num_Pt_dep = len(partition.P_t_dep)
    num_Pt_interproc = len(partition.P_t_interproc)
    num_Pt_legacy = len(partition.P_t_legacy)

    record = CaseAuditRecord(
        case_id=case_id,
        project=case_cfg["project"],
        cve=case_cfg["cve"],
        target_binary=case_cfg["target_binary"],
        vulnerable_version=case_cfg["vulnerable_version"],
        fixed_commit=case_cfg["fixed_commit"],
        expected_sanitizer=exp_oracle["sanitizer"],
        expected_function=exp_oracle["function"],
        expected_file=exp_oracle["file"],
        expected_line=exp_oracle["line"],
        observed_sanitizer=san_report.error_type,
        observed_function=obs_fn,
        observed_file=obs_file,
        observed_line=obs_line,
        oracle_reproduced=oracle_reproduced,
        target_bb=target_bb,
        fault_bb_in_trace=fault_bb_in_trace,
        fault_bb_in_dep_slice=partition.fault_bb_in_dep_slice,
        analysis_incomplete=partition.analysis_incomplete,
        slice_quality=partition.slice_quality,
        supervision_suitability=partition.supervision_suitability,
        missing_fault_operands=partition.missing_fault_operands,
        fault_operand_coverage=partition.fault_operand_coverage,
        quality_rationale=partition.quality_rationale,
        num_nodes_V=num_V,
        num_edges=len(edges_df),
        num_executed_Et=num_Et,
        num_slice_dep=num_St_dep,
        num_slice_interproc=num_St_interproc,
        num_slice_legacy=num_St_legacy,
        num_reachable_exec=num_Rt_exec,
        num_weak_positives_dep=num_Pt_dep,
        num_weak_positives_interproc=num_Pt_interproc,
        num_weak_positives_legacy=num_Pt_legacy,
        retention_dep=round(partition.retention_dep, 6),
        retention_interproc=round(partition.retention_interproc, 6),
        retention_legacy=round(partition.retention_legacy, 6),
        trace_coverage=round(num_Et / num_V, 6) if num_V > 0 else 0.0,
        slice_coverage=round(num_St_dep / num_V, 6) if num_V > 0 else 0.0,
        positive_yield=num_Pt_dep,
        num_slice_St=num_St_dep,
        num_reachability_Rt=num_Rt_exec,
        num_weak_positives_Pt=num_Pt_dep,
        num_unknown_unexecuted_Ut=len(partition.U_t),
        num_executed_non_slice_Ct=len(partition.C_t),
        num_verified_negatives_Nt=len(partition.N_t),
        has_verified_negatives=partition.has_verified_negatives,
        training_recommendation=rec,
    )

    if return_context:
        ablation = compute_slicing_ablation(edges_df, target_bb, partition.E_t)
        return record, ablation, partition.diagnostics

    return record


def run_full_label_audit(
    config_path: Path,
    cases_root: Path,
    output_dir: Path,
) -> List[CaseAuditRecord]:
    """Run label yield audit across all configured cases and emit audit reports."""
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    records: List[CaseAuditRecord] = []
    ablation_rows: List[Dict[str, Any]] = []
    diag_dir = output_dir / "diagnostics"
    diag_dir.mkdir(parents=True, exist_ok=True)

    for c in cfg["cases"]:
        record, ab, diag = audit_case(c, cases_root, return_context=True)
        records.append(record)

        with open(diag_dir / f"slice_diagnostics_{record.case_id}.json", "w", encoding="utf-8") as f:
            json.dump(diag, f, indent=2)

        ablation_rows.append({
            "case_id": record.case_id,
            "target_function": record.observed_function,
            "num_executed_Et": ab["num_executed_Et"],
            "slice_legacy": ab["slice_legacy"],
            "retention_legacy": f"{ab['retention_legacy']:.4f}",
            "slice_ssa_only": ab["slice_ssa_only"],
            "retention_ssa_only": f"{ab['retention_ssa_only']:.4f}",
            "slice_ssa_cdg": ab["slice_ssa_cdg"],
            "retention_ssa_cdg": f"{ab['retention_ssa_cdg']:.4f}",
            "slice_must_mem_cdg": ab["slice_must_mem_cdg"],
            "retention_must_mem_cdg": f"{ab['retention_must_mem_cdg']:.4f}",
            "slice_all_dep": ab["slice_all_dep"],
            "retention_all_dep": f"{ab['retention_all_dep']:.4f}",
            "slice_interprocedural": ab["slice_interprocedural"],
            "retention_interprocedural": f"{ab['retention_interprocedural']:.4f}",
            "trace_retention": f"{record.retention_dep:.4f}",
            "fault_operand_coverage": format_optional_coverage(ab["fault_operand_coverage"]),
            "analysis_incomplete": record.analysis_incomplete,
            "slice_quality": record.slice_quality,
            "supervision_suitability": record.supervision_suitability,
            "num_reachable_exec": ab["num_reachable_exec"],
        })

    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. JSON report
    json_path = output_dir / "label_yield_audit.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in records], f, indent=2)

    # 2. CSV reports
    csv_path = output_dir / "label_yield_audit.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(records[0]).keys()))
        writer.writeheader()
        for r in records:
            writer.writerow(asdict(r))

    comp_csv_path = output_dir / "before_after_comparison.csv"
    with open(comp_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "case_id",
            "num_nodes_V",
            "num_executed_Et",
            "num_slice_legacy",
            "num_slice_dep",
            "num_slice_interproc",
            "num_reachable_exec",
            "num_weak_positives_legacy",
            "num_weak_positives_dep",
            "num_weak_positives_interproc",
            "retention_legacy",
            "retention_dep",
            "retention_interproc",
            "fault_bb_in_trace",
            "fault_bb_in_dep_slice",
            "fault_operand_coverage",
            "analysis_incomplete",
            "slice_quality",
            "supervision_suitability",
        ])
        for r in records:
            writer.writerow([
                r.case_id,
                r.num_nodes_V,
                r.num_executed_Et,
                r.num_slice_legacy,
                r.num_slice_dep,
                r.num_slice_interproc,
                r.num_reachable_exec,
                r.num_weak_positives_legacy,
                r.num_weak_positives_dep,
                r.num_weak_positives_interproc,
                f"{r.retention_legacy:.4f}",
                f"{r.retention_dep:.4f}",
                f"{r.retention_interproc:.4f}",
                r.fault_bb_in_trace,
                r.fault_bb_in_dep_slice,
                format_optional_coverage(r.fault_operand_coverage),
                r.analysis_incomplete,
                r.slice_quality,
                r.supervision_suitability,
            ])

    oracle_csv_path = output_dir / "oracle_verification.csv"
    with open(oracle_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "expected_sanitizer", "expected_location", "observed_sanitizer", "observed_location", "oracle_match", "fixed_commit"])
        for r in records:
            exp_loc = f"{r.expected_function} at {Path(r.expected_file).name}:{r.expected_line}"
            obs_loc = f"{r.observed_function} at {Path(r.observed_file).name}:{r.observed_line}"
            writer.writerow([r.case_id, r.expected_sanitizer, exp_loc, r.observed_sanitizer, obs_loc, r.oracle_reproduced, r.fixed_commit[:12]])

    # 4. Multi-relation ablation CSV
    ablation_csv_path = output_dir / "slicing_ablation_comparison.csv"
    with open(ablation_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(ablation_rows[0].keys()))
        writer.writeheader()
        for row in ablation_rows:
            writer.writerow(row)

    # 5. Provenance audit JSON and toolchain comparison CSV
    generate_provenance_audit(records, output_dir)
    generate_toolchain_comparison(output_dir)

    # 6. Markdown report referencing CSV files
    md_path = output_dir / "label_yield_audit.md"
    md_content = generate_markdown_audit_report(records, ablation_rows, output_dir)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    return records


def format_optional_coverage(value: Optional[float], digits: int = 2) -> str:
    """Render unknown operand coverage without misleading 0% or 100%."""
    return "UNKNOWN" if value is None else f"{value:.{digits}f}"


def generate_provenance_audit(records: List[CaseAuditRecord], output_dir: Path) -> Path:
    """Emit an honest evidence inventory, not fabricated instruction paths.

    A verified instruction-level provenance extractor is not yet implemented.
    The graph's BB-to-BB relation paths are NOT operand-level evidence.
    """
    payload = {
        "schema_version": 2,
        "verification_status": "NOT_VERIFIED",
        "reason": "Instruction-level operand IDs, def-use provenance and validated callsite contexts are not exported.",
        "cases": {
            r.case_id: {
                "target_bb": r.target_bb,
                "fault_operand_coverage": None,
                "verified_operand_paths": [],
                "analysis_incomplete": True,
                "supervision_suitability": r.supervision_suitability,
            }
            for r in records
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "provenance_audit.json"
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, allow_nan=False)
    return path


def generate_toolchain_comparison(output_dir: Path) -> Path:
    """Create an explicitly unmeasured comparison, never prefilled timings."""
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "toolchain_comparison.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "case_id", "tool", "bitcode_sha256", "tool_version",
            "command", "exit_code", "wall_seconds", "raw_log_path",
            "verification_status",
        ])
    with open(output_dir / "toolchain_comparison.status.json", "w", encoding="utf-8") as handle:
        json.dump({
            "verification_status": "NOT_MEASURED",
            "reason": "No reproducible raw tool runs supplied to this audit pipeline.",
            "required": ["bitcode_sha256", "tool_version", "command", "exit_code", "wall_seconds", "raw_log_path"],
        }, handle, indent=2)
    return csv_path


def generate_markdown_audit_report(
    records: List[CaseAuditRecord],
    ablation_rows: Optional[List[Dict[str, Any]]] = None,
    output_dir: Optional[Path] = None,
) -> str:
    """Report only measured graph partition counts, with provenance disclaimers."""
    lines = [
        "# Target Graph Label-Yield Audit",
        "",
        "**Status:** Graph slicing metrics are exploratory. Instruction-level fault",
        "operand provenance and independent DG/SVF benchmarks are NOT VERIFIED.",
        "No case is eligible for validated target-specific supervision.",
        "Unknown BBs remain unlabeled. nnPU requires separate assumption checks.",
        "",
        "| Case | Executed BB | Local slice | Interproc candidate slice | Local retention | Gate |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for r in records:
        lines.append(
            f"| {r.case_id} | {r.num_executed_Et} | {r.num_slice_dep} | "
            f"{r.num_slice_interproc} | {r.retention_dep:.2%} | {r.supervision_suitability} |"
        )
    lines.extend([
        "",
        "Interprocedural counts use current coarse BB-level candidate edges,",
        "not context-sensitive SDG value-flow proof.",
        "",
        "## Evidence status",
        "",
        "- `provenance_audit.json`: NOT_VERIFIED (no fabricated chains).",
        "- `toolchain_comparison.csv`: no benchmark entries without raw logs.",
        "- `slicing_ablation_comparison.csv`: relation-filter sensitivity, not precision.",
        "- `fault_operand_coverage`: UNKNOWN until verified instruction-level tracing exists.",
        "",
    ])
    return "\n".join(lines)



def main():
    import argparse
    parser = argparse.ArgumentParser(description="Run Label-Yield Audit across benchmark cases.")
    parser.add_argument("--config", type=Path, default=Path("/home/user/workspace/nycu-dissertation/target_graph/configs/projects/cases.yaml"))
    parser.add_argument("--cases-root", type=Path, default=Path("/home/user/workspace/nycu-dissertation/target_graph/cases"))
    parser.add_argument("--output-dir", type=Path, default=Path("/home/user/workspace/nycu-dissertation/target_graph/reports"))
    args = parser.parse_args()

    records = run_full_label_audit(
        config_path=args.config,
        cases_root=args.cases_root,
        output_dir=args.output_dir,
    )
    print(f"Successfully audited {len(records)} cases. Reports saved to {args.output_dir}")


if __name__ == "__main__":
    main()



"""Evidence-only LLVM target audit using canonical direct BB execution.

This module NEVER chooses or rewrites a target. A source line may identify
multiple inlined owners; the actual faulting operand is not established by
a matching source line or a reached SVFG node.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from target_graph.tracing.evidence import source_path_matches

_VALUE_OPCODES = frozenset({
    "load", "store", "getelementptr", "call", "invoke", "atomicrmw",
    "cmpxchg", "icmp", "fcmp", "phi", "select", "bitcast",
})


def _match_loc(loc: dict, source: str, line: int) -> bool:
    try:
        loc_line = int(loc.get("line") or 0)
    except (ValueError, TypeError):
        return False
    return bool(line > 0 and loc_line == line and
                source_path_matches(str(loc.get("file") or ""), source))


def inspect_target(
    bb_records: Mapping[str, dict],
    executed_bbs: set[str],
    oracle: dict[str, Any],
    canonical_target_inst: str,
    before_path: Path,
    *,
    v2_nodes_path: Path | None = None,
    max_reported_bbs: int = 128,
    max_reported_instructions: int = 256,
) -> dict[str, Any]:
    """Inspect ALL exact debug-location owners, never silently pick one.

    Owner function is the LLVM function containing each BB, not necessarily
    the source function from inlined DebugLoc. A source match is not proof of
    the crash-causing LLVM instruction. Preserve full cardinalities even if
    output samples are capped.
    """
    source = str(oracle.get("relative_source_file") or "")
    try:
        line = int(oracle.get("line") or 0)
    except (ValueError, TypeError):
        line = 0
    target_bb = canonical_target_inst.rsplit(":", 1)[0] if ":" in canonical_target_inst else ""
    matches: list[dict[str, Any]] = []
    for bb_id, rec in bb_records.items():
        locs = [loc for loc in rec.get("debug_locations", [])
                if isinstance(loc, dict) and _match_loc(loc, source, line)]
        if locs:
            matches.append({
                "bb_id": bb_id,
                "llvm_owner_function": rec.get("function", ""),
                "executed_in_direct_trace": bb_id in executed_bbs,
                "matching_debug_locations": locs,
                "is_current_target": bb_id == target_bb,
            })
    matches.sort(key=lambda x: (
        not x["executed_in_direct_trace"], not x["is_current_target"],
        x["llvm_owner_function"], x["bb_id"],
    ))
    matched_ids = {item["bb_id"] for item in matches}
    wanted = set(matched_ids)
    if target_bb:
        wanted.add(target_bb)
    instructions: list[dict[str, Any]] = []
    matching_instruction_count = 0
    target_in_ir = False
    if before_path.is_file():
        with before_path.open(encoding="utf-8") as handle:
            for line_no, raw in enumerate(handle, 1):
                if not raw.strip():
                    continue
                rec = json.loads(raw)
                inst_id = rec.get("inst_id") or rec.get("id")
                if inst_id == canonical_target_inst:
                    target_in_ir = True
                bb_id = rec.get("bb_id")
                if bb_id not in wanted:
                    continue
                # Preserve all candidate counts, but limit report size.
                matching_instruction_count += 1
                if len(instructions) < max_reported_instructions:
                    instructions.append({
                        "instruction_id": inst_id,
                        "bb_id": bb_id,
                        "opcode": rec.get("opcode"),
                        "llvm_owner_function": rec.get("function"),
                        "executed_in_direct_trace": bb_id in executed_bbs,
                        "source_line_candidate": bb_id in matched_ids,
                        "value_flow_relevant_opcode": rec.get("opcode") in _VALUE_OPCODES,
                        "is_current_target": inst_id == canonical_target_inst,
                    })
    inline_metadata_status = "V2_NODES_NOT_AVAILABLE"
    instruction_debugloc_matches = 0
    v2_instruction_metadata_matched = 0
    if v2_nodes_path is not None and v2_nodes_path.is_file():
        by_inst_id = {row["instruction_id"]: row for row in instructions
                      if isinstance(row.get("instruction_id"), str)}
        remaining = set(by_inst_id)
        with v2_nodes_path.open(encoding="utf-8") as handle:
            for line_no, raw in enumerate(handle, 1):
                if not remaining:
                    break
                if not raw.strip():
                    continue
                node = json.loads(raw)
                inst_id = node.get("id")
                if inst_id not in remaining or node.get("kind") != "instruction":
                    continue
                row = by_inst_id[inst_id]
                # Same opaque ID is not sufficient if two compiled versions
                # accidentally share a stale/forged identity. Check BB/opcode/
                # owning LLVM function before treating V2 DebugLoc as evidence.
                if (node.get("bb_id") != row["bb_id"] or
                        node.get("text") != row["opcode"] or
                        node.get("function") != row["llvm_owner_function"]):
                    row["v2_identity_mismatch"] = True
                    remaining.remove(inst_id)
                    continue
                v2_instruction_metadata_matched += 1
                row["v2_instruction_identity_verified"] = True
                row["instruction_source_file"] = node.get("source_file")
                row["instruction_line"] = node.get("line")
                row["instruction_exact_oracle_source_line"] = _match_loc(
                    {"file": node.get("source_file"), "line": node.get("line")},
                    source, line
                )
                if (row["instruction_exact_oracle_source_line"] and
                        row["source_line_candidate"]):
                    instruction_debugloc_matches += 1
                chain = node.get("inline_callsite_chain")
                if isinstance(chain, list):
                    row["inline_callsite_chain"] = chain
                remaining.remove(inst_id)
        with_chains = sum("inline_callsite_chain" in row for row in instructions)
        if not v2_instruction_metadata_matched:
            inline_metadata_status = "V2_IDS_NOT_ALIGNED_OR_STALE"
        else:
            inline_metadata_status = (
                "LLVM_V2_INLINED_AT_AVAILABLE"
                if with_chains else "V2_MISSING_INLINE_CHAIN_FIELD_REBUILD_ANALYSIS_V2"
            )

    target_in_graph = target_bb in bb_records
    target_executed = target_bb in executed_bbs
    if not target_in_graph:
        status = "TARGET_NOT_IN_CURRENT_GRAPH"
    elif not before_path.is_file():
        status = "MISSING_ORIGINAL_INST_MAP"
    elif not target_in_ir:
        status = "TARGET_NOT_IN_CURRENT_IR"
    elif not target_executed:
        status = "TARGET_NOT_EXECUTED"
    else:
        status = "TARGET_EXECUTED"

    return {
        "schema_version": 1,
        "analysis": "ORACLE_SOURCE_LINE_TO_LLVM_OWNERS_DIAGNOSTIC_ONLY",
        "status": status,
        "safe_for_automatic_retarget": False,
        "requires_fault_operand_and_inline_review": True,
        "expected_oracle": {
            "relative_source_file": source,
            "line": line,
            "function": oracle.get("function"),
        },
        "canonical_target_inst": canonical_target_inst,
        "canonical_target_bb": target_bb,
        "target_in_graph": target_in_graph,
        "target_in_original_ir": target_in_ir if before_path.is_file() else None,
        "target_executed": target_executed,
        "oracle_bb_count": len(matches),
        "executed_oracle_bb_count": sum(m["executed_in_direct_trace"] for m in matches),
        "oracle_bbs": [m["bb_id"] for m in matches],
        "executed_oracle_bbs": [m["bb_id"] for m in matches if m["executed_in_direct_trace"]],
        "candidate_owner_bbs": matches[:max_reported_bbs],
        "candidate_owner_bbs_truncated": len(matches) > max_reported_bbs,
        "instruction_count_in_matching_and_target_bbs": matching_instruction_count,
        "candidate_instructions": instructions,
        "inline_metadata_status": inline_metadata_status,
        "v2_instruction_metadata_matched": v2_instruction_metadata_matched,
        "exact_oracle_instruction_debugloc_matches": instruction_debugloc_matches,
        "candidate_instructions_truncated": matching_instruction_count > max_reported_instructions,
        "notes": [
            "Direct BB hit is exact BB-entry coverage, not proof of faulting operand",
            "Matching debug source line may refer to different inlined LLVM owners",
            "An instruction in an oracle-line BB does NOT necessarily have the oracle DebugLoc",
            "No candidate is automatically promoted to canonical_target_inst",
            "Use ASan stack/PC and LLVM DILocation inlinedAt before retargeting",
        ],
    }

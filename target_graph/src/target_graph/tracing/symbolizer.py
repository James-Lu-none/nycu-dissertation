"""Symbolize execution traces and map runtime PCs to Basic Block IDs."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from target_graph.llvm.mapping import BasicBlockMapper


def find_llvm_symbolizer() -> Optional[str]:
    """Locate llvm-symbolizer binary."""
    for cand in ["llvm-symbolizer-14", "llvm-symbolizer", "llvm-symbolizer-15", "llvm-symbolizer-16"]:
        path = shutil.which(cand)
        if path:
            return path
    return None


def parse_trace_pcs(trace_file: Path) -> List[int]:
    """Parse sequential PCs from trace file."""
    if not trace_file.exists():
        return []
    pcs: List[int] = []
    with open(trace_file, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 2:
                # Format is "seq: 0x..."
                hex_str = parts[1]
                try:
                    pcs.append(int(hex_str, 16))
                except ValueError:
                    continue
    return pcs


def symbolize_pcs(
    pcs: List[int],
    binary_path: Path,
    symbolizer_path: Optional[str] = None,
) -> Dict[int, List[Tuple[str, str, int]]]:
    """Batch symbolize PCs using llvm-symbolizer.
    
    Returns mapping: pc -> list of (func_name, source_file, line_number)
    where multiple entries represent inlined call frames (innermost first).
    """
    if not pcs:
        return {}
    if symbolizer_path is None:
        symbolizer_path = find_llvm_symbolizer()

    hex_pcs = [f"0x{pc:x}" for pc in pcs]
    if symbolizer_path:
        cmd = [symbolizer_path, f"--obj={binary_path}"] + hex_pcs
    else:
        # Fallback to Docker target-graph:llvm14
        binary_abs = binary_path.resolve()
        parent_dir = binary_abs.parent
        bin_name = binary_abs.name
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{parent_dir}:/bin_dir",
            "target-graph:llvm14",
            "llvm-symbolizer", f"--obj=/bin_dir/{bin_name}"
        ] + hex_pcs

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        return {}

    # llvm-symbolizer separates output for each input address by an empty line (\n\n)
    raw_blocks = res.stdout.split("\n\n")
    blocks = [b.strip() for b in raw_blocks if b.strip()]
    pc_to_locs: Dict[int, List[Tuple[str, str, int]]] = {}

    for idx, pc in enumerate(pcs):
        if idx >= len(blocks):
            pc_to_locs[pc] = []
            continue

        b = blocks[idx]
        lines = b.splitlines()
        locs: List[Tuple[str, str, int]] = []
        i = 0
        while i + 1 < len(lines):
            fn = lines[i].strip()
            loc_str = lines[i + 1].strip()
            i += 2
            if loc_str and "??" not in loc_str:
                parts = loc_str.rsplit(":", 2)
                if len(parts) >= 2:
                    file_path = parts[0]
                    try:
                        line_no = int(parts[1])
                        if line_no > 0:
                            locs.append((fn, file_path, line_no))
                    except ValueError:
                        pass
        pc_to_locs[pc] = locs

    # Forward probe for unmapped preamble PCs (e.g. line 0 compiler preamble at return address)
    unmapped = [p for p in pcs if not pc_to_locs.get(p)]
    if unmapped:
        for off in [4, 8, 16]:
            still_unmapped = [p for p in unmapped if not pc_to_locs.get(p)]
            if not still_unmapped:
                break
            probe_pcs = [p + off for p in still_unmapped]
            # Call helper directly on probe_pcs without recursion
            hex_probes = [f"0x{p:x}" for p in probe_pcs]
            if symbolizer_path:
                probe_cmd = [symbolizer_path, f"--obj={binary_path}"] + hex_probes
            else:
                binary_abs = binary_path.resolve()
                probe_cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{binary_abs.parent}:/bin_dir",
                    "target-graph:llvm14",
                    "llvm-symbolizer", f"--obj=/bin_dir/{binary_abs.name}"
                ] + hex_probes
            res_probe = subprocess.run(probe_cmd, capture_output=True, text=True)
            if res_probe.returncode == 0:
                probe_blocks = [b.strip() for b in res_probe.stdout.split("\n\n") if b.strip()]
                for p_idx, orig_p in enumerate(still_unmapped):
                    if p_idx < len(probe_blocks):
                        plines = probe_blocks[p_idx].splitlines()
                        pi = 0
                        plocs: List[Tuple[str, str, int]] = []
                        while pi + 1 < len(plines):
                            pfn = plines[pi].strip()
                            ploc_str = plines[pi + 1].strip()
                            pi += 2
                            if ploc_str and "??" not in ploc_str:
                                pparts = ploc_str.rsplit(":", 2)
                                if len(pparts) >= 2:
                                    try:
                                        pln = int(pparts[1])
                                        if pln > 0:
                                            plocs.append((pfn, pparts[0], pln))
                                    except ValueError:
                                        pass
                        if plocs:
                            pc_to_locs[orig_p] = plocs

    return pc_to_locs


def trace_to_basic_blocks(
    trace_file: Path,
    binary_path: Path,
    bb_mapper: BasicBlockMapper,
    symbolizer_path: Optional[str] = None,
) -> List[str]:
    """Map ordered trace events to an ordered list of basic block IDs."""
    pcs = parse_trace_pcs(trace_file)
    if not pcs:
        return []

    # Symbolize unique PCs to save time
    unique_pcs = list(dict.fromkeys(pcs))
    pc_map = symbolize_pcs(unique_pcs, binary_path, symbolizer_path=symbolizer_path)

    ordered_bbs: List[str] = []
    for pc in pcs:
        locs = pc_map.get(pc, [])
        matched_bbs: List[str] = []

        # Check innermost frame first, then inlined caller frames
        for fn, file_path, line_no in locs:
            matched_bbs = bb_mapper.map_source_location(file_path, line_no, function_name=fn)
            if matched_bbs:
                break

        if not matched_bbs and locs:
            # Fallback without function filtering if not matched
            for _, file_path, line_no in locs:
                matched_bbs = bb_mapper.map_source_location(file_path, line_no)
                if matched_bbs:
                    break

        if matched_bbs:
            for bb in matched_bbs:
                if not ordered_bbs or ordered_bbs[-1] != bb:
                    ordered_bbs.append(bb)

    return ordered_bbs

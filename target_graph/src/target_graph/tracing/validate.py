"""Reproducibility validation for PoC runs across vulnerable and patched targets."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
from .sanitizer import SanitizerReport, parse_sanitizer_output


@dataclass
class RunResult:
    exit_code: int
    stdout: str
    stderr: str
    trace_file_path: Optional[str]
    sanitizer_report: Optional[SanitizerReport]


@dataclass
class ReproducerValidation:
    is_vulnerable_reproducible: bool
    is_fixed_safe: bool
    vulnerable_error_type: Optional[str]
    fixed_error_type: Optional[str]
    vulnerable_runs: int
    vulnerable_repro_count: int
    fixed_runs: int
    status: str  # verified_bug, flaky_bug, unverified, patch_still_crashes


def verify_poc_reproducibility(
    vulnerable_runs: List[RunResult],
    fixed_runs: List[RunResult],
    min_repro_count: int = 3,
) -> ReproducerValidation:
    """Verify that vulnerable build reproducibly triggers expected bug and patched does not."""
    vul_repros = [r for r in vulnerable_runs if r.sanitizer_report is not None]
    fixed_repros = [r for r in fixed_runs if r.sanitizer_report is not None]

    is_vul_repro = len(vul_repros) >= min_repro_count
    is_fixed_safe = len(fixed_repros) == 0

    vul_error = vul_repros[0].sanitizer_report.error_type if vul_repros else None
    fixed_error = fixed_repros[0].sanitizer_report.error_type if fixed_repros else None

    if is_vul_repro and is_fixed_safe:
        status = "verified_bug"
    elif is_vul_repro and not is_fixed_safe:
        status = "patch_still_crashes"
    elif 0 < len(vul_repros) < min_repro_count:
        status = "flaky_bug"
    else:
        status = "unverified"

    return ReproducerValidation(
        is_vulnerable_reproducible=is_vul_repro,
        is_fixed_safe=is_fixed_safe,
        vulnerable_error_type=vul_error,
        fixed_error_type=fixed_error,
        vulnerable_runs=len(vulnerable_runs),
        vulnerable_repro_count=len(vul_repros),
        fixed_runs=len(fixed_runs),
        status=status,
    )


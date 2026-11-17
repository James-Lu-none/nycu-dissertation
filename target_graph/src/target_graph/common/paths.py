"""Path resolution and standard directory conventions for target_graph."""
from __future__ import annotations

import os
from pathlib import Path

TARGET_GRAPH_ROOT = Path(__file__).resolve().parents[3]
NYCU_ROOT = TARGET_GRAPH_ROOT.parent
BENCH_DIR = NYCU_ROOT / "bench"
CASES_DIR = TARGET_GRAPH_ROOT / "cases"
CONFIGS_DIR = TARGET_GRAPH_ROOT / "configs"
DOCKER_DIR = TARGET_GRAPH_ROOT / "docker"
SCRIPTS_DIR = TARGET_GRAPH_ROOT / "scripts"
TESTS_DIR = TARGET_GRAPH_ROOT / "tests"


def case_dir(case_id: str) -> Path:
    """Return the output directory for a specific case."""
    return CASES_DIR / case_id


def case_variant_dir(case_id: str, variant: str) -> Path:
    """Return the output directory for a specific case variant ('vulnerable' or 'fixed')."""
    return CASES_DIR / case_id / variant


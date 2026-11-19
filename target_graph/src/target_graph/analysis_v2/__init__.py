"""Instruction-level value-flow analysis (experimental, not certified SDG)."""

from .graph import DependencyEdge, DependencyGraph, DependencyNode
from .slicing import SliceResult, backward_slice

__all__ = [
    "DependencyEdge",
    "DependencyGraph",
    "DependencyNode",
    "SliceResult",
    "backward_slice",
]

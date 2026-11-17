"""Structured logging utilities."""
from __future__ import annotations

import logging
import sys
from rich.logging import RichHandler


def get_logger(name: str = "target_graph") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = RichHandler(
            rich_tracebacks=True,
            show_time=True,
            show_path=False,
            markup=True,
        )
        logger.addHandler(handler)
        logger.propagate = False
    return logger


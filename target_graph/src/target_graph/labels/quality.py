"""Label-Yield Audit reporting utilities per Section 5."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List
import pandas as pd

from .slicing import SlicePartition


@dataclass
class CaseAuditReport:
    case_id: str
    project: str
    build_id: str
    target_bb: str
    fault_pc: str
    sanitizer_type: str
    build_success: bool
    reproducer_verified: bool
    partition_counts: Dict[str, int]
    negative_yield_ratio: float
    status: str  # eligible_for_ranking, no_verified_negatives, build_failed, unverified_crash


class LabelYieldAuditor:
    def __init__(self) -> None:
        self.reports: List[CaseAuditReport] = []

    def record_case(self, report: CaseAuditReport) -> None:
        self.reports.append(report)

    def to_dataframe(self) -> pd.DataFrame:
        rows = []
        for r in self.reports:
            row = {
                "case_id": r.case_id,
                "project": r.project,
                "target_bb": r.target_bb,
                "sanitizer": r.sanitizer_type,
                "status": r.status,
                "neg_yield": f"{r.negative_yield_ratio:.1%}",
            }
            row.update(r.partition_counts)
            rows.append(row)
        return pd.DataFrame(rows)

    def save_audit(self, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        # JSON output
        json_path = output_dir / "label_yield_audit.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in self.reports], f, indent=2)

        # CSV / Parquet
        df = self.to_dataframe()
        df.to_csv(output_dir / "label_yield_audit.csv", index=False)

        # Markdown summary
        md_path = output_dir / "label_yield_audit.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("# Target-Conditioned Label-Yield Audit Report\n\n")
            f.write(df.to_markdown(index=False) if hasattr(df, "to_markdown") else str(df))
            f.write("\n")


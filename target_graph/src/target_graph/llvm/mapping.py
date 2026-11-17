"""Map debug locations and runtime PCs to Basic Block IDs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class BasicBlockMapper:
    def __init__(self, bb_map_path: Path) -> None:
        self.bb_map_path = bb_map_path
        self.bb_records: Dict[str, Dict] = {}  # bb_id -> record
        self.line_to_bbs: Dict[Tuple[str, int], List[str]] = {}  # (file_basename, line) -> [bb_id]
        self._load()

    def _load(self) -> None:
        if not self.bb_map_path.exists():
            raise FileNotFoundError(f"Missing {self.bb_map_path}")

        with open(self.bb_map_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                rec = json.loads(line)
                bb_id = rec["bb_id"]
                self.bb_records[bb_id] = rec

                for loc in rec.get("debug_locations", []):
                    fn = Path(loc.get("file", "")).name
                    ln = int(loc.get("line", 0))
                    if ln > 0 and fn:
                        key = (fn, ln)
                        if key not in self.line_to_bbs:
                            self.line_to_bbs[key] = []
                        if bb_id not in self.line_to_bbs[key]:
                            self.line_to_bbs[key].append(bb_id)

    def map_source_location(
        self,
        file_path: str,
        line: int,
        function_name: Optional[str] = None,
    ) -> List[str]:
        """Find BB IDs containing this source location, optionally filtered by function."""
        fn = Path(file_path).name
        bbs = self.line_to_bbs.get((fn, line), [])
        if function_name:
            # Prioritize BBs belonging to the exact or matching function
            exact_bbs = [
                b for b in bbs
                if self.bb_records.get(b, {}).get("function") == function_name
            ]
            if exact_bbs:
                return exact_bbs
            relaxed_bbs = [
                b for b in bbs
                if function_name in self.bb_records.get(b, {}).get("function", "")
                or self.bb_records.get(b, {}).get("function", "") in function_name
            ]
            if relaxed_bbs:
                return relaxed_bbs
        return bbs

    def get_function_bbs(self, function_name: str) -> List[str]:
        """Find all BB IDs belonging to a function."""
        return [
            bb_id
            for bb_id, rec in self.bb_records.items()
            if rec.get("function") == function_name
        ]


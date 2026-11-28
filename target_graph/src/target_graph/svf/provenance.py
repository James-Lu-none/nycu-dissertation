"""Select canonical LLVM identity provenance, never derive it from case aliases.

TargetGraphPass hashes (build_id, module_name, function, BB ordinal).
The dataset directory can be an alias for a previously exported canonical
case. This module validates the original graph's pass_summary.json and
returns only the two hashing inputs, not instructions or vulnerability labels.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def canonical_identity(summary: Path, bitcode_name: str) -> tuple[str, str]:
    if not summary.is_file():
        raise ValueError(
            f"Missing {summary}; run the original full-graph export "
            "before attempting SVF analysis"
        )
    data = json.loads(summary.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Original graph provenance must be a JSON object")
    build_id, module_name = data.get("build_id"), data.get("module_name")
    if any(not isinstance(s, str) or not s.strip() or "\n" in s
           for s in (build_id, module_name)):
        raise ValueError("Missing or invalid canonical build_id/module_name")
    if not bitcode_name or Path(module_name).name != bitcode_name:
        raise ValueError(
            "Bitcode file name differs from original graph's module_name: "
            f"{bitcode_name!r} != {Path(module_name).name!r}; "
            "do not assume these graphs came from the same LLVM module"
        )
    return build_id, module_name


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pass-summary", type=Path, required=True)
    p.add_argument("--bitcode-name", required=True)
    args = p.parse_args()
    build_id, module_name = canonical_identity(
        args.pass_summary, args.bitcode_name
    )
    # Two lines for safe bash mapfile; newlines in the source are rejected.
    print(build_id)
    print(module_name)


if __name__ == "__main__":
    main()

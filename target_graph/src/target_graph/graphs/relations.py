"""Relation vocabulary and categorical integer IDs for multi-relational graphs."""
from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Dict, List, Tuple


class ProgramRelation(str, Enum):
    CFG_T = "CFG_T"
    CFG_F = "CFG_F"
    CFG_NEXT = "CFG_NEXT"
    CFG_OTHER = "CFG_OTHER"
    DDG_SSA = "DDG_SSA"
    DDG_MEM = "DDG_MEM"
    CDG = "CDG"
    CALL = "CALL"
    RETURN = "RETURN"
    PARAM_IN = "PARAM_IN"
    PARAM_OUT = "PARAM_OUT"
    CALLSITE_SUMMARY = "CALLSITE_SUMMARY"


# Core canonical program relations (0 through 11)
CANONICAL_RELATION_TO_ID: Dict[str, int] = {
    ProgramRelation.CFG_T.value: 0,
    ProgramRelation.CFG_F.value: 1,
    ProgramRelation.CFG_NEXT.value: 2,
    ProgramRelation.CFG_OTHER.value: 3,
    ProgramRelation.DDG_SSA.value: 4,
    ProgramRelation.DDG_MEM.value: 5,
    ProgramRelation.CDG.value: 6,
    ProgramRelation.CALL.value: 7,
    ProgramRelation.RETURN.value: 8,
    ProgramRelation.PARAM_IN.value: 9,
    ProgramRelation.PARAM_OUT.value: 10,
    ProgramRelation.CALLSITE_SUMMARY.value: 11,
}

ID_TO_CANONICAL_RELATION: Dict[int, str] = {v: k for k, v in CANONICAL_RELATION_TO_ID.items()}

NUM_CANONICAL_RELATIONS: int = len(CANONICAL_RELATION_TO_ID)

# Message-passing relations optionally include reverse edges (REV_*)
MESSAGE_RELATION_TO_ID: Dict[str, int] = dict(CANONICAL_RELATION_TO_ID)
for name, cid in list(CANONICAL_RELATION_TO_ID.items()):
    MESSAGE_RELATION_TO_ID[f"REV_{name}"] = cid + NUM_CANONICAL_RELATIONS

NUM_MESSAGE_RELATIONS: int = len(MESSAGE_RELATION_TO_ID)


def dump_relation_vocab(path: Path, include_reverse: bool = False) -> None:
    """Save versioned relation_to_id.json."""
    vocab = MESSAGE_RELATION_TO_ID if include_reverse else CANONICAL_RELATION_TO_ID
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vocab, f, indent=2)


def load_relation_vocab(path: Path) -> Dict[str, int]:
    """Load relation_to_id.json."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


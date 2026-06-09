from __future__ import annotations

import hashlib
from typing import Any


def ordered_pair_record(pair_key: str, sides: dict[int, dict[str, Any]]) -> dict[str, Any]:
    if set(sides) != {0, 1}:
        raise ValueError("pair record requires safe and vulnerable orientations")
    vulnerable_first = int(hashlib.sha256(pair_key.encode("utf-8")).hexdigest()[:8], 16) % 2 == 1
    order = [1, 0] if vulnerable_first else [0, 1]
    return {
        "pair_key": pair_key,
        "text_0": sides[order[0]]["text"],
        "text_1": sides[order[1]]["text"],
        "label": 0 if vulnerable_first else 1,
        "orientation_labels": order,
    }


def build_ordered_pair_records(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[int, dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["pair_key"]), {})[int(row["label"])] = row
    return [
        ordered_pair_record(pair_key, sides)
        for pair_key, sides in sorted(grouped.items())
        if set(sides) == {0, 1}
    ]


def summarize_ordered_pairs(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "pairs": len(records),
        "target_0": sum(int(row["label"]) == 0 for row in records),
        "target_1": sum(int(row["label"]) == 1 for row in records),
    }

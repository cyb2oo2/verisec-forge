from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vrf.io_utils import read_jsonl, write_json, write_jsonl


def extract_diff(text: str) -> str:
    marker = "Unified diff:"
    if marker not in text:
        return text
    return text.split(marker, 1)[1].strip()


def changed_line_bucket(pair_text: str) -> tuple[int, str]:
    added = 0
    removed = 0
    for line in extract_diff(pair_text).splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    changed = added + removed
    if changed <= 2:
        return changed, "00-02"
    if changed <= 5:
        return changed, "03-05"
    if changed <= 10:
        return changed, "06-10"
    if changed <= 25:
        return changed, "11-25"
    return changed, "26+"


def is_mixed_risk_vulnerable(row: dict[str, Any]) -> bool:
    text = str(row.get("pair_text") or "")
    has_protection_signal = "candidate_adds_protection" in text
    has_risk_signal = "candidate_introduces_risk" in text or "candidate_removes_protection" in text
    return bool(row.get("has_vulnerability")) and has_protection_signal and has_risk_signal


def is_safe_anchor(row: dict[str, Any]) -> bool:
    text = str(row.get("pair_text") or "")
    has_safe_signal = "candidate_adds_protection" in text or "candidate_removes_risk" in text
    return not bool(row.get("has_vulnerability")) and has_safe_signal


def duplicate_row(row: dict[str, Any], *, suffix: str) -> dict[str, Any]:
    duplicated = dict(row)
    duplicated["id"] = f"{row['id']}::{suffix}"
    duplicated["recall_recovery_source_id"] = row["id"]
    duplicated["recall_recovery_augmented"] = True
    return duplicated


def build_dataset(
    directional_rows: list[dict[str, Any]],
    raw_rows: list[dict[str, Any]],
    *,
    mixed_repeats: int,
    all_vulnerable_26plus_repeats: int,
    safe_anchor_count: int,
    seed: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw_by_id = {row["id"]: row for row in raw_rows}
    enriched: list[dict[str, Any]] = []
    vulnerable_26plus: list[dict[str, Any]] = []
    mixed_vulnerable_26plus: list[dict[str, Any]] = []
    safe_26plus_anchors: list[dict[str, Any]] = []

    for row in directional_rows:
        raw_row = raw_by_id[row["id"]]
        changed_lines, bucket = changed_line_bucket(str(raw_row.get("pair_text") or raw_row.get("prompt") or ""))
        base = dict(row)
        base["changed_lines"] = changed_lines
        base["changed_line_bucket"] = bucket
        base["recall_recovery_augmented"] = False
        enriched.append(base)
        if bucket != "26+":
            continue
        if bool(row.get("has_vulnerability")):
            vulnerable_26plus.append(base)
            if is_mixed_risk_vulnerable(base):
                mixed_vulnerable_26plus.append(base)
        elif is_safe_anchor(base):
            safe_26plus_anchors.append(base)

    rng = random.Random(seed)
    selected_safe_anchors = list(safe_26plus_anchors)
    rng.shuffle(selected_safe_anchors)
    selected_safe_anchors = selected_safe_anchors[:safe_anchor_count]

    augmented = list(enriched)
    for repeat in range(all_vulnerable_26plus_repeats):
        for row in vulnerable_26plus:
            augmented.append(duplicate_row(row, suffix=f"rr_v26_{repeat}"))
    for repeat in range(mixed_repeats):
        for row in mixed_vulnerable_26plus:
            augmented.append(duplicate_row(row, suffix=f"rr_mixed26_{repeat}"))
    for index, row in enumerate(selected_safe_anchors):
        augmented.append(duplicate_row(row, suffix=f"rr_safe26_{index}"))

    rng.shuffle(augmented)
    summary = {
        "base_rows": len(enriched),
        "output_rows": len(augmented),
        "added_rows": len(augmented) - len(enriched),
        "seed": seed,
        "selection": {
            "vulnerable_26plus": len(vulnerable_26plus),
            "mixed_vulnerable_26plus": len(mixed_vulnerable_26plus),
            "safe_26plus_anchor_candidates": len(safe_26plus_anchors),
            "safe_26plus_anchors_added": len(selected_safe_anchors),
            "mixed_repeats": mixed_repeats,
            "all_vulnerable_26plus_repeats": all_vulnerable_26plus_repeats,
        },
        "labels": {
            "vulnerable": sum(1 for row in augmented if bool(row.get("has_vulnerability"))),
            "safe": sum(1 for row in augmented if not bool(row.get("has_vulnerability"))),
        },
    }
    return augmented, summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a direction-aware recall-recovery PrimeVul train set.")
    parser.add_argument("--directional-input", required=True)
    parser.add_argument("--raw-input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", required=True)
    parser.add_argument("--mixed-repeats", type=int, default=2)
    parser.add_argument("--all-vulnerable-26plus-repeats", type=int, default=1)
    parser.add_argument("--safe-anchor-count", type=int, default=40)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rows, summary = build_dataset(
        read_jsonl(args.directional_input),
        read_jsonl(args.raw_input),
        mixed_repeats=args.mixed_repeats,
        all_vulnerable_26plus_repeats=args.all_vulnerable_26plus_repeats,
        safe_anchor_count=args.safe_anchor_count,
        seed=args.seed,
    )
    write_jsonl(args.output, rows)
    write_json(args.summary_output, summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

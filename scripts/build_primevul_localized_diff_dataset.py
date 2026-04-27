from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.build_primevul_pair_context_dataset import localize_pair_diff
from vrf.io_utils import read_jsonl, write_json, write_jsonl


def extract_diff(text: str) -> str:
    marker = "Unified diff:"
    if marker not in text:
        return text
    return text.split(marker, 1)[1].strip() + "\n"


def build_localized_text(row: dict[str, Any], *, max_chars: int, max_hunks: int) -> tuple[str, bool, int, int]:
    original_text = str(row.get("pair_text") or row.get("prompt") or "")
    pair_diff = extract_diff(original_text)
    localized_diff = localize_pair_diff(pair_diff, max_chars=max_chars, max_hunks=max_hunks)
    metadata = (
        f"Project: {row.get('project') or 'unknown'}\n"
        f"CVE: {row.get('cve') or 'unknown'}\n"
        f"CWE: {row.get('vulnerability_type') or 'unknown'}\n"
    )
    localized_text = (
        "Task: decide whether the candidate side of this localized diff is the vulnerable version.\n"
        "The diff is from paired_counterpart to candidate. Long diffs are reduced to repair-relevant hunks.\n\n"
        f"{metadata}\n"
        "Localized unified diff:\n"
        f"{localized_diff}\n"
    )
    return localized_text, localized_diff != pair_diff, len(original_text), len(localized_text)


def percentile(values: list[int], quantile: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    index = min(len(sorted_values) - 1, max(0, round((len(sorted_values) - 1) * quantile)))
    return float(sorted_values[index])


def summarize_lengths(rows: list[dict[str, Any]]) -> dict[str, Any]:
    original_lengths = [int(row["localized_diff_original_chars"]) for row in rows]
    localized_lengths = [int(row["localized_diff_chars"]) for row in rows]
    return {
        "rows": len(rows),
        "localized_rows": sum(1 for row in rows if bool(row["localized_diff_applied"])),
        "original_chars": {
            "mean": round(statistics.mean(original_lengths), 2) if original_lengths else 0.0,
            "p50": percentile(original_lengths, 0.5),
            "p90": percentile(original_lengths, 0.9),
            "max": max(original_lengths) if original_lengths else 0,
        },
        "localized_chars": {
            "mean": round(statistics.mean(localized_lengths), 2) if localized_lengths else 0.0,
            "p50": percentile(localized_lengths, 0.5),
            "p90": percentile(localized_lengths, 0.9),
            "max": max(localized_lengths) if localized_lengths else 0,
        },
    }


def localize_rows(rows: list[dict[str, Any]], *, max_chars: int, max_hunks: int) -> list[dict[str, Any]]:
    localized_rows: list[dict[str, Any]] = []
    for row in rows:
        localized_text, applied, original_chars, localized_chars = build_localized_text(
            row,
            max_chars=max_chars,
            max_hunks=max_hunks,
        )
        enriched = dict(row)
        enriched["pair_text"] = localized_text
        enriched["pair_text_mode"] = "diff_localized"
        enriched["localized_diff_applied"] = applied
        enriched["localized_diff_original_chars"] = original_chars
        enriched["localized_diff_chars"] = localized_chars
        localized_rows.append(enriched)
    return localized_rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Rewrite existing PrimeVul diff-only rows as localized-diff rows.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", required=True)
    parser.add_argument("--max-chars", type=int, default=3600)
    parser.add_argument("--max-hunks", type=int, default=6)
    args = parser.parse_args()

    rows = read_jsonl(args.input)
    localized_rows = localize_rows(rows, max_chars=args.max_chars, max_hunks=args.max_hunks)
    write_jsonl(args.output, localized_rows)
    summary = {
        "input": args.input,
        "output": args.output,
        "max_chars": args.max_chars,
        "max_hunks": args.max_hunks,
        **summarize_lengths(localized_rows),
    }
    write_json(args.summary_output, summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

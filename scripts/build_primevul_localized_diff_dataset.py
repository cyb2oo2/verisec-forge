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

from scripts.build_primevul_pair_context_dataset import _hunk_score, _split_diff_hunks, localize_pair_diff
from vrf.io_utils import read_jsonl, write_json, write_jsonl


def extract_diff(text: str) -> str:
    marker = "Unified diff:"
    if marker not in text:
        return text
    return text.split(marker, 1)[1].strip() + "\n"


def _clip_text(text: str, *, max_chars: int, marker: str) -> str:
    if len(text) <= max_chars:
        return text
    budget = max(0, max_chars - len(marker) - 2)
    return text[:budget].rstrip() + "\n" + marker + "\n"


def _hunk_to_contrastive_window(hunk: list[str]) -> str:
    counterpart_lines: list[str] = []
    candidate_lines: list[str] = []
    context_lines: list[str] = []
    header = hunk[0] if hunk else "@@"
    for line in hunk[1:]:
        if line.startswith("-") and not line.startswith("---"):
            counterpart_lines.append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            candidate_lines.append(line[1:])
        elif line.startswith(" "):
            context_lines.append(line[1:])
    return (
        f"Hunk: {header}\n"
        "Shared context:\n"
        f"{_format_block(context_lines)}\n"
        "Counterpart side removed/old lines:\n"
        f"{_format_block(counterpart_lines)}\n"
        "Candidate side added/new lines:\n"
        f"{_format_block(candidate_lines)}\n"
    )


def _format_block(lines: list[str]) -> str:
    if not lines:
        return "  <none>"
    return "\n".join(f"  {line}" for line in lines[:12])


def contrastive_pair_diff(pair_diff: str, *, max_chars: int, max_hunks: int) -> str:
    headers, hunks = _split_diff_hunks(pair_diff)
    if not hunks:
        return _clip_text(pair_diff, max_chars=max_chars, marker="[contrastive diff truncated]")
    ranked = sorted(enumerate(hunks), key=lambda item: _hunk_score(item[1]), reverse=True)
    selected = [hunk for _index, hunk in ranked[:max_hunks]]
    rendered = [
        "[contrastive diff windows: counterpart is the paired reference; candidate is the side to judge]",
        *headers[:2],
    ]
    for index, hunk in enumerate(selected, start=1):
        rendered.append(f"\nWindow {index}:")
        rendered.append(_hunk_to_contrastive_window(hunk))
    omitted = max(0, len(hunks) - len(selected))
    rendered.append(f"[contrastive windows kept {len(selected)} of {len(hunks)} hunks; omitted {omitted}]")
    return _clip_text(
        "\n".join(rendered) + "\n",
        max_chars=max_chars,
        marker="[contrastive diff truncated to fit character budget]",
    )


def build_localized_text(
    row: dict[str, Any],
    *,
    max_chars: int,
    max_hunks: int,
    mode: str = "localized",
) -> tuple[str, bool, int, int, str]:
    original_text = str(row.get("pair_text") or row.get("prompt") or "")
    pair_diff = extract_diff(original_text)
    if mode == "contrastive":
        localized_diff = contrastive_pair_diff(pair_diff, max_chars=max_chars, max_hunks=max_hunks)
        title = "contrastive localized diff"
        body = "Long diffs are reduced to paired counterpart-vs-candidate changed windows."
        heading = "Contrastive changed windows:"
        text_mode = "diff_contrastive_localized"
    else:
        localized_diff = localize_pair_diff(pair_diff, max_chars=max_chars, max_hunks=max_hunks)
        title = "localized diff"
        body = "Long diffs are reduced to repair-relevant hunks."
        heading = "Localized unified diff:"
        text_mode = "diff_localized"
    metadata = (
        f"Project: {row.get('project') or 'unknown'}\n"
        f"CVE: {row.get('cve') or 'unknown'}\n"
        f"CWE: {row.get('vulnerability_type') or 'unknown'}\n"
    )
    localized_text = (
        f"Task: decide whether the candidate side of this {title} is the vulnerable version.\n"
        f"The diff is from paired_counterpart to candidate. {body}\n\n"
        f"{metadata}\n"
        f"{heading}\n"
        f"{localized_diff}\n"
    )
    return localized_text, localized_diff != pair_diff, len(original_text), len(localized_text), text_mode


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


def localize_rows(rows: list[dict[str, Any]], *, max_chars: int, max_hunks: int, mode: str = "localized") -> list[dict[str, Any]]:
    localized_rows: list[dict[str, Any]] = []
    for row in rows:
        localized_text, applied, original_chars, localized_chars, text_mode = build_localized_text(
            row,
            max_chars=max_chars,
            max_hunks=max_hunks,
            mode=mode,
        )
        enriched = dict(row)
        enriched["pair_text"] = localized_text
        enriched["pair_text_mode"] = text_mode
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
    parser.add_argument("--mode", choices=["localized", "contrastive"], default="localized")
    args = parser.parse_args()

    rows = read_jsonl(args.input)
    localized_rows = localize_rows(rows, max_chars=args.max_chars, max_hunks=args.max_hunks, mode=args.mode)
    write_jsonl(args.output, localized_rows)
    summary = {
        "input": args.input,
        "output": args.output,
        "max_chars": args.max_chars,
        "max_hunks": args.max_hunks,
        "mode": args.mode,
        **summarize_lengths(localized_rows),
    }
    write_json(args.summary_output, summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

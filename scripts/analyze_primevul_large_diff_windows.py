from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.build_primevul_pair_context_dataset import SECURITY_KEYWORDS, _hunk_score, _split_diff_hunks
from scripts.build_primevul_localized_diff_dataset import extract_diff
from vrf.io_utils import read_jsonl, write_json


def confusion(gold: int, pred: int) -> str:
    if gold == 1 and pred == 1:
        return "tp"
    if gold == 0 and pred == 0:
        return "tn"
    if gold == 0 and pred == 1:
        return "fp"
    return "fn"


def changed_lines(hunk: list[str]) -> list[str]:
    return [
        line
        for line in hunk
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    ]


def keyword_hits(text: str) -> list[str]:
    lower = text.lower()
    return sorted(keyword for keyword in SECURITY_KEYWORDS if keyword in lower)


def summarize_hunk(hunk: list[str]) -> dict[str, Any]:
    changed = changed_lines(hunk)
    added = [line[1:] for line in changed if line.startswith("+")]
    removed = [line[1:] for line in changed if line.startswith("-")]
    text = "\n".join(changed)
    return {
        "header": hunk[0] if hunk else "",
        "score": list(_hunk_score(hunk)),
        "changed_lines": len(changed),
        "added_lines": len(added),
        "removed_lines": len(removed),
        "keywords": keyword_hits(text),
        "removed_preview": removed[:6],
        "added_preview": added[:6],
    }


def top_hunks(pair_text: str, *, limit: int) -> list[dict[str, Any]]:
    diff = extract_diff(pair_text)
    _headers, hunks = _split_diff_hunks(diff)
    ranked = sorted(hunks, key=_hunk_score, reverse=True)
    return [summarize_hunk(hunk) for hunk in ranked[:limit]]


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    keyword_counts: Counter[str] = Counter()
    project_counts: Counter[str] = Counter()
    cwe_counts: Counter[str] = Counter()
    for row in rows:
        project_counts[str(row.get("project") or "unknown")] += 1
        cwe_counts[str(row.get("vulnerability_type") or "unknown")] += 1
        for hunk in row["top_hunks"]:
            keyword_counts.update(hunk["keywords"])
    return {
        "count": len(rows),
        "top_projects": project_counts.most_common(8),
        "top_cwes": cwe_counts.most_common(8),
        "top_keywords": keyword_counts.most_common(12),
    }


def build_analysis(
    dataset_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
    *,
    threshold: float,
    hunk_limit: int,
) -> dict[str, Any]:
    data_by_id = {row["id"]: row for row in dataset_rows}
    joined: list[dict[str, Any]] = []
    for pred_row in prediction_rows:
        row_id = pred_row["id"]
        data = data_by_id[row_id]
        prob = float(pred_row["vuln_probability"])
        pred = int(prob >= threshold)
        gold = int(pred_row.get("gold", int(bool(data.get("has_vulnerability")))))
        outcome = confusion(gold, pred)
        pair_text = str(data.get("pair_text") or data.get("prompt") or "")
        hunks = top_hunks(pair_text, limit=hunk_limit)
        joined.append(
            {
                "id": row_id,
                "project": data.get("project", "unknown"),
                "cve": data.get("cve", "unknown"),
                "vulnerability_type": data.get("vulnerability_type", "unknown"),
                "gold": gold,
                "pred": pred,
                "outcome": outcome,
                "vuln_probability": round(prob, 4),
                "top_hunks": hunks,
            }
        )

    outcomes = Counter(row["outcome"] for row in joined)
    errors = [row for row in joined if row["outcome"] in {"fp", "fn"}]
    fps = sorted((row for row in joined if row["outcome"] == "fp"), key=lambda row: row["vuln_probability"], reverse=True)
    fns = sorted((row for row in joined if row["outcome"] == "fn"), key=lambda row: row["vuln_probability"])
    return {
        "summary": {
            "threshold": threshold,
            "rows": len(joined),
            "tp": int(outcomes["tp"]),
            "tn": int(outcomes["tn"]),
            "fp": int(outcomes["fp"]),
            "fn": int(outcomes["fn"]),
            "error_count": len(errors),
        },
        "false_positive_aggregate": aggregate(fps),
        "false_negative_aggregate": aggregate(fns),
        "top_false_positives": fps[:8],
        "top_false_negatives": fns[:8],
    }


def render_hunk(hunk: dict[str, Any]) -> list[str]:
    lines = [
        f"- Hunk `{hunk['header']}` score `{hunk['score']}` changed `{hunk['changed_lines']}` keywords `{', '.join(hunk['keywords']) or 'none'}`",
    ]
    if hunk["removed_preview"]:
        lines.append(f"- Removed: `{' | '.join(hunk['removed_preview'])[:180]}`")
    if hunk["added_preview"]:
        lines.append(f"- Added: `{' | '.join(hunk['added_preview'])[:180]}`")
    return lines


def render_examples(title: str, rows: list[dict[str, Any]]) -> list[str]:
    lines = [f"## {title}", ""]
    for row in rows:
        lines.extend(
            [
                f"### {row['id']}",
                "",
                f"- Project: `{row['project']}`",
                f"- CWE: `{row['vulnerability_type']}`",
                f"- Gold/Pred/Prob: `{row['gold']}` / `{row['pred']}` / `{row['vuln_probability']}`",
            ]
        )
        for hunk in row["top_hunks"]:
            lines.extend(render_hunk(hunk))
        lines.append("")
    return lines


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# PrimeVul Large-Diff Error Window Analysis",
        "",
        "This report mines high-scoring diff windows from `26+` bucket predictions.",
        "",
        "## Summary",
        "",
        f"- Threshold: `{summary['threshold']}`",
        f"- Rows: `{summary['rows']}`",
        f"- TP/TN/FP/FN: `{summary['tp']}` / `{summary['tn']}` / `{summary['fp']}` / `{summary['fn']}`",
        "",
        "## Aggregate Signals",
        "",
        f"- FP top keywords: `{payload['false_positive_aggregate']['top_keywords']}`",
        f"- FN top keywords: `{payload['false_negative_aggregate']['top_keywords']}`",
        f"- FP top projects: `{payload['false_positive_aggregate']['top_projects']}`",
        f"- FN top projects: `{payload['false_negative_aggregate']['top_projects']}`",
        "",
        *render_examples("Top False Positives", payload["top_false_positives"]),
        *render_examples("Top False Negatives", payload["top_false_negatives"]),
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Mine PrimeVul large-diff error windows from classifier predictions.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--threshold", type=float, required=True)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output", required=True)
    parser.add_argument("--hunk-limit", type=int, default=2)
    args = parser.parse_args()

    payload = build_analysis(
        read_jsonl(args.dataset),
        read_jsonl(args.predictions),
        threshold=args.threshold,
        hunk_limit=args.hunk_limit,
    )
    write_json(args.json_output, payload)
    md_path = Path(args.md_output)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()

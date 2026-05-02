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

from scripts.analyze_primevul_predicted_side_failures import gap_bucket, mistake_type, top_counts
from vrf.io_utils import read_jsonl, write_json, write_jsonl


def rows_by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row["id"]): row for row in rows}


def build_inversion_rows(
    dataset_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
    *,
    min_gap: float,
) -> list[dict[str, Any]]:
    dataset = rows_by_id(dataset_rows)
    inversions: list[dict[str, Any]] = []
    for prediction in prediction_rows:
        gold = int(prediction["gold"])
        pred = int(prediction["pred"])
        gap = float(prediction.get("pair_probability_gap") or 0.0)
        if gold == pred or gap < min_gap:
            continue
        source = dataset.get(str(prediction["id"]))
        if not source:
            continue
        inversions.append(
            {
                "id": prediction["id"],
                "pair_key": prediction.get("pair_key") or source.get("pair_key"),
                "gold": gold,
                "pred": pred,
                "mistake_type": mistake_type(gold, pred),
                "vuln_probability": float(prediction.get("vuln_probability") or 0.0),
                "pair_probability_gap": gap,
                "gap_bucket": gap_bucket(gap),
                "changed_lines": prediction.get("changed_lines"),
                "changed_line_bucket": prediction.get("changed_line_bucket"),
                "route": prediction.get("route"),
                "pre_coupled_pred": prediction.get("pre_coupled_pred"),
                "project": source.get("project"),
                "cve": source.get("cve"),
                "vulnerability_type": source.get("vulnerability_type"),
                "commit_id": source.get("commit_id"),
                "file_name": source.get("file_name"),
                "pair_counterpart_id": source.get("pair_counterpart_id"),
                "pair_text_mode": source.get("pair_text_mode"),
                "pair_text": source.get("pair_text"),
                "code": source.get("code"),
                "commit_message": source.get("commit_message"),
                "cve_desc": source.get("cve_desc"),
                "calibration_target": gold,
                "negative_predicted_side": pred,
            }
        )
    return sorted(inversions, key=lambda row: float(row["pair_probability_gap"]), reverse=True)


def summarize(rows: list[dict[str, Any]], *, min_gap: float, top_n: int) -> dict[str, Any]:
    mistake_counts = Counter(str(row["mistake_type"]) for row in rows)
    gap_values = [float(row["pair_probability_gap"]) for row in rows]
    return {
        "config": {
            "min_gap": min_gap,
            "top_n": top_n,
        },
        "summary": {
            "rows": len(rows),
            "pair_groups": len({str(row["pair_key"]) for row in rows}),
            "false_positives": mistake_counts["false_positive"],
            "false_negatives": mistake_counts["false_negative"],
            "avg_gap": round(sum(gap_values) / len(gap_values), 4) if gap_values else 0.0,
            "min_gap_observed": round(min(gap_values), 4) if gap_values else 0.0,
            "max_gap_observed": round(max(gap_values), 4) if gap_values else 0.0,
        },
        "breakdowns": {
            "by_mistake_type": top_counts([str(row["mistake_type"]) for row in rows], limit=top_n),
            "by_changed_line_bucket": top_counts([str(row["changed_line_bucket"]) for row in rows], limit=top_n),
            "by_project": top_counts([str(row["project"]) for row in rows], limit=top_n),
            "by_vulnerability_type": top_counts([str(row["vulnerability_type"]) for row in rows], limit=top_n),
            "by_route": top_counts([str(row["route"]) for row in rows], limit=top_n),
        },
        "examples": [
            {
                key: row.get(key)
                for key in [
                    "id",
                    "pair_key",
                    "mistake_type",
                    "gold",
                    "pred",
                    "pair_probability_gap",
                    "changed_line_bucket",
                    "project",
                    "vulnerability_type",
                    "cve",
                    "file_name",
                ]
            }
            for row in rows[:top_n]
        ],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# PrimeVul Confident Side-Inversion Set",
        "",
        "This report builds a hard-negative calibration set from pair-coupled predictions that are wrong with a large probability gap. It targets confident side inversions rather than ambiguous near-ties.",
        "",
        "## Summary",
        "",
        f"- Minimum gap: `{payload['config']['min_gap']}`",
        f"- Rows: `{summary['rows']}`",
        f"- Pair groups: `{summary['pair_groups']}`",
        f"- False positives / false negatives: `{summary['false_positives']}` / `{summary['false_negatives']}`",
        f"- Avg gap: `{summary['avg_gap']}`",
        f"- Gap range: `{summary['min_gap_observed']}` - `{summary['max_gap_observed']}`",
        "",
    ]
    for name, rows in payload["breakdowns"].items():
        lines.extend([f"## {name}", "", "| value | count |", "| --- | ---: |"])
        for row in rows:
            lines.append(f"| {row['value']} | {row['count']} |")
        lines.append("")
    lines.extend(["## Highest-Gap Examples", "", "| id | type | gap | bucket | project | cwe | cve |", "| --- | --- | ---: | --- | --- | --- | --- |"])
    for row in payload["examples"]:
        lines.append(
            f"| {row['id']} | {row['mistake_type']} | {round(float(row['pair_probability_gap']), 4)} | {row['changed_line_bucket']} | {row['project']} | {row['vulnerability_type']} | {row['cve']} |"
        )
    lines.extend(
        [
            "",
            "## Intended Use",
            "",
            "Use this as a targeted calibration or hard-negative mining artifact for pair-side decision models. It should not be treated as an independent benchmark split because it is selected from current model failures.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a confident side-inversion hard-negative set for PrimeVul pair decisions.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--min-gap", type=float, default=0.5)
    parser.add_argument("--top-n", type=int, default=20)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--summary-md")
    args = parser.parse_args()

    rows = build_inversion_rows(
        read_jsonl(args.dataset),
        read_jsonl(args.predictions),
        min_gap=args.min_gap,
    )
    payload = summarize(rows, min_gap=args.min_gap, top_n=args.top_n)
    write_jsonl(args.output, rows)
    write_json(args.summary_json, payload)
    if args.summary_md:
        output = Path(args.summary_md)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()

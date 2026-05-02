from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vrf.io_utils import read_jsonl, write_json


def prediction_by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row["id"]): row for row in rows}


def group_hunks(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row["source_id"])].append(row)
    return grouped


def top_hunk(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    return max(rows, key=lambda row: float(row.get("predicted_side_aware_score", 0.0)))


def top_counts(values: list[str], *, limit: int) -> list[dict[str, Any]]:
    return [{"value": key, "count": count} for key, count in Counter(values).most_common(limit)]


def gap_bucket(value: float) -> str:
    if value < 0.02:
        return "00-02"
    if value < 0.05:
        return "02-05"
    if value < 0.10:
        return "05-10"
    if value < 0.20:
        return "10-20"
    if value < 0.50:
        return "20-50"
    return "50+"


def mistake_type(gold: int, pred: int) -> str:
    if gold == 1 and pred == 0:
        return "false_negative"
    if gold == 0 and pred == 1:
        return "false_positive"
    return "correct"


def summarize_sources(
    hunk_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
    *,
    top_n: int,
) -> dict[str, Any]:
    predictions = prediction_by_id(prediction_rows)
    grouped = group_hunks(hunk_rows)
    source_summaries: list[dict[str, Any]] = []
    for source_id, hunks in grouped.items():
        prediction = predictions.get(source_id)
        if not prediction:
            continue
        gold = int(prediction["gold"])
        pred = int(prediction["pred"])
        top = top_hunk(hunks)
        source_summaries.append(
            {
                "source_id": source_id,
                "pair_key": prediction.get("pair_key"),
                "gold": gold,
                "pred": pred,
                "mistake_type": mistake_type(gold, pred),
                "project": top.get("project") if top else None,
                "cve": top.get("cve") if top else None,
                "vulnerability_type": top.get("vulnerability_type") if top else None,
                "changed_line_bucket": prediction.get("changed_line_bucket"),
                "changed_lines": prediction.get("changed_lines"),
                "route": prediction.get("route"),
                "pair_coupled": bool(prediction.get("pair_coupled", False)),
                "pair_probability_gap": float(prediction.get("pair_probability_gap") or 0.0),
                "gap_bucket": gap_bucket(float(prediction.get("pair_probability_gap") or 0.0)),
                "vuln_probability": float(prediction.get("vuln_probability") or 0.0),
                "pre_coupled_pred": prediction.get("pre_coupled_pred"),
                "top_pseudo_label": int(top.get("pseudo_label", 0)) if top else 0,
                "top_header": top.get("header") if top else "",
                "top_direction_labels": top.get("direction_labels", []) if top else [],
                "top_risk_support": top.get("risk_support") if top else 0,
                "top_safety_support": top.get("safety_support") if top else 0,
                "top_score": float(top.get("predicted_side_aware_score") or 0.0) if top else 0.0,
            }
        )
    wrong = [row for row in source_summaries if row["mistake_type"] != "correct"]
    correct = [row for row in source_summaries if row["mistake_type"] == "correct"]
    labels = [
        label
        for row in wrong
        for label in row["top_direction_labels"]
    ]
    return {
        "summary": {
            "matched_sources": len(source_summaries),
            "correct_sources": len(correct),
            "wrong_sources": len(wrong),
            "side_accuracy": round(len(correct) / len(source_summaries), 4) if source_summaries else 0.0,
            "false_positives": sum(1 for row in wrong if row["mistake_type"] == "false_positive"),
            "false_negatives": sum(1 for row in wrong if row["mistake_type"] == "false_negative"),
            "top_hunk_positive_rate_wrong": round(sum(1 for row in wrong if row["top_pseudo_label"] == 1) / len(wrong), 4) if wrong else 0.0,
            "top_hunk_positive_rate_correct": round(sum(1 for row in correct if row["top_pseudo_label"] == 1) / len(correct), 4) if correct else 0.0,
        },
        "wrong_breakdowns": {
            "by_mistake_type": top_counts([row["mistake_type"] for row in wrong], limit=top_n),
            "by_changed_line_bucket": top_counts([str(row["changed_line_bucket"]) for row in wrong], limit=top_n),
            "by_gap_bucket": top_counts([row["gap_bucket"] for row in wrong], limit=top_n),
            "by_project": top_counts([str(row["project"]) for row in wrong], limit=top_n),
            "by_vulnerability_type": top_counts([str(row["vulnerability_type"]) for row in wrong], limit=top_n),
            "by_top_direction_label": top_counts(labels, limit=top_n),
            "by_route": top_counts([str(row["route"]) for row in wrong], limit=top_n),
        },
        "wrong_examples": sorted(wrong, key=lambda row: abs(row["top_score"]), reverse=True)[:top_n],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# PrimeVul Predicted-Side Failure Taxonomy",
        "",
        "This report analyzes rows where pair-coupled predicted side disagrees with the gold side, then inspects the top hunk selected by the predicted-side localizer.",
        "",
        "## Summary",
        "",
        f"- Matched sources: `{summary['matched_sources']}`",
        f"- Side accuracy: `{summary['side_accuracy']}`",
        f"- Wrong sources: `{summary['wrong_sources']}`",
        f"- False positives / false negatives: `{summary['false_positives']}` / `{summary['false_negatives']}`",
        f"- Wrong top-hunk positive rate: `{summary['top_hunk_positive_rate_wrong']}`",
        f"- Correct top-hunk positive rate: `{summary['top_hunk_positive_rate_correct']}`",
        "",
    ]
    for name, rows in payload["wrong_breakdowns"].items():
        lines.extend([f"## {name}", "", "| value | count |", "| --- | ---: |"])
        for row in rows:
            lines.append(f"| {row['value']} | {row['count']} |")
        lines.append("")
    lines.extend(["## High-Score Wrong Examples", "", "| source_id | type | bucket | gap | project | cwe | top_labels | top_score |", "| --- | --- | --- | ---: | --- | --- | --- | ---: |"])
    for row in payload["wrong_examples"]:
        labels = ",".join(row["top_direction_labels"])
        lines.append(
            f"| {row['source_id']} | {row['mistake_type']} | {row['changed_line_bucket']} | {round(row['pair_probability_gap'], 4)} | {row['project']} | {row['vulnerability_type']} | {labels} | {round(row['top_score'], 4)} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A low wrong top-hunk positive rate means the localizer is ranking evidence that aligns with the predicted side but disagrees with the gold side. In this run, wrong-side rows are therefore not mainly a hunk-ranking failure; they are upstream side-decision failures that propagate into evidence selection. The next lever is pair-side decision calibration and hard negative handling.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze predicted-side hunk-localizer failure modes.")
    parser.add_argument("--scored-hunks", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--top-n", type=int, default=20)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    args = parser.parse_args()

    payload = summarize_sources(
        read_jsonl(args.scored_hunks),
        read_jsonl(args.predictions),
        top_n=args.top_n,
    )
    write_json(args.json_output, payload)
    if args.md_output:
        output = Path(args.md_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()

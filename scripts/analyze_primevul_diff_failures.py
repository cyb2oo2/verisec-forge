from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vrf.io_utils import read_jsonl, write_json


def _safe_text(value: Any) -> str:
    return str(value or "")


def _extract_diff(pair_text: str) -> str:
    marker = "Unified diff:"
    if marker not in pair_text:
        return pair_text
    return pair_text.split(marker, 1)[1].strip()


def _diff_stats(pair_text: str) -> dict[str, int]:
    diff = _extract_diff(pair_text)
    added = 0
    removed = 0
    hunks = 0
    for line in diff.splitlines():
        if line.startswith("@@"):
            hunks += 1
        elif line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return {
        "diff_chars": len(diff),
        "added_lines": added,
        "removed_lines": removed,
        "changed_lines": added + removed,
        "hunks": hunks,
    }


def _length_bucket(changed_lines: int) -> str:
    if changed_lines <= 2:
        return "00-02"
    if changed_lines <= 5:
        return "03-05"
    if changed_lines <= 10:
        return "06-10"
    if changed_lines <= 25:
        return "11-25"
    return "26+"


def _confidence_bucket(probability: float) -> str:
    confidence = max(probability, 1.0 - probability)
    if confidence >= 0.95:
        return "0.95-1.00"
    if confidence >= 0.80:
        return "0.80-0.95"
    if confidence >= 0.65:
        return "0.65-0.80"
    return "0.50-0.65"


def _confusion(gold: int, pred: int) -> str:
    if gold == 1 and pred == 1:
        return "tp"
    if gold == 0 and pred == 0:
        return "tn"
    if gold == 0 and pred == 1:
        return "fp"
    return "fn"


def _rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)


def _summarize_group(rows: list[dict[str, Any]], key: str, *, limit: int = 12) -> list[dict[str, Any]]:
    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        value = _safe_text(row.get(key)) or "unknown"
        grouped[value][row["outcome"]] += 1
        grouped[value]["total"] += 1

    summary: list[dict[str, Any]] = []
    for value, counts in grouped.items():
        total = int(counts["total"])
        errors = int(counts["fp"] + counts["fn"])
        summary.append(
            {
                key: value,
                "total": total,
                "errors": errors,
                "error_rate": _rate(errors, total),
                "fp": int(counts["fp"]),
                "fn": int(counts["fn"]),
                "tp": int(counts["tp"]),
                "tn": int(counts["tn"]),
            }
        )
    return sorted(summary, key=lambda item: (-item["errors"], -item["total"], str(item[key])))[:limit]


def _top_examples(rows: list[dict[str, Any]], outcome: str, *, limit: int = 8) -> list[dict[str, Any]]:
    selected = [row for row in rows if row["outcome"] == outcome]
    if outcome == "fp":
        selected.sort(key=lambda row: row["vuln_probability"], reverse=True)
    elif outcome == "fn":
        selected.sort(key=lambda row: row["vuln_probability"])
    else:
        selected.sort(key=lambda row: max(row["vuln_probability"], 1.0 - row["vuln_probability"]), reverse=True)
    examples: list[dict[str, Any]] = []
    for row in selected[:limit]:
        commit_lines = _safe_text(row.get("commit_message")).splitlines()
        examples.append(
            {
                "id": row["id"],
                "project": row.get("project", "unknown"),
                "cve": row.get("cve", "unknown"),
                "cwe": row.get("vulnerability_type", "unknown"),
                "gold": row["gold"],
                "pred": row["pred"],
                "vuln_probability": round(float(row["vuln_probability"]), 4),
                "changed_lines": row["changed_lines"],
                "commit_url": row.get("commit_url"),
                "commit_message": (commit_lines[0] if commit_lines else "")[:160],
            }
        )
    return examples


def build_failure_analysis(
    dataset_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
    *,
    threshold: float,
) -> dict[str, Any]:
    dataset_by_id = {row["id"]: row for row in dataset_rows}
    joined: list[dict[str, Any]] = []
    for pred_row in prediction_rows:
        row_id = pred_row["id"]
        data = dataset_by_id[row_id]
        probability = float(pred_row["vuln_probability"])
        pred = int(probability >= threshold)
        gold = int(pred_row.get("gold", int(bool(data.get("has_vulnerability")))))
        stats = _diff_stats(_safe_text(data.get("pair_text") or data.get("prompt")))
        enriched = {
            **data,
            **stats,
            "id": row_id,
            "gold": gold,
            "pred": pred,
            "vuln_probability": probability,
            "outcome": _confusion(gold, pred),
            "changed_line_bucket": _length_bucket(stats["changed_lines"]),
            "confidence_bucket": _confidence_bucket(probability),
        }
        joined.append(enriched)

    counts = Counter(row["outcome"] for row in joined)
    total = len(joined)
    errors = counts["fp"] + counts["fn"]
    metrics = {
        "threshold": threshold,
        "num_examples": total,
        "accuracy": _rate(counts["tp"] + counts["tn"], total),
        "recall": _rate(counts["tp"], counts["tp"] + counts["fn"]),
        "specificity": _rate(counts["tn"], counts["tn"] + counts["fp"]),
        "precision": _rate(counts["tp"], counts["tp"] + counts["fp"]),
        "false_positive_rate": _rate(counts["fp"], counts["fp"] + counts["tn"]),
        "false_negative_rate": _rate(counts["fn"], counts["fn"] + counts["tp"]),
        "error_rate": _rate(errors, total),
        "tp": int(counts["tp"]),
        "tn": int(counts["tn"]),
        "fp": int(counts["fp"]),
        "fn": int(counts["fn"]),
    }

    return {
        "summary": metrics,
        "by_cwe": _summarize_group(joined, "vulnerability_type"),
        "by_project": _summarize_group(joined, "project"),
        "by_changed_line_bucket": _summarize_group(joined, "changed_line_bucket"),
        "by_confidence_bucket": _summarize_group(joined, "confidence_bucket"),
        "top_false_positives": _top_examples(joined, "fp"),
        "top_false_negatives": _top_examples(joined, "fn"),
    }


def _table(rows: list[dict[str, Any]], key: str) -> list[str]:
    lines = [
        f"| {key} | Total | Errors | Error Rate | FP | FN | TP | TN |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            f"| {row[key]} | {row['total']} | {row['errors']} | {row['error_rate']:.4f} | "
            f"{row['fp']} | {row['fn']} | {row['tp']} | {row['tn']} |"
        )
    return lines


def _examples_table(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| ID | Project | CWE | Gold | Pred | Prob | Changed Lines | CVE |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in rows:
        cve = row.get("cve") or "unknown"
        lines.append(
            f"| {row['id']} | {row['project']} | {row['cwe']} | {row['gold']} | {row['pred']} | "
            f"{row['vuln_probability']:.4f} | {row['changed_lines']} | {cve} |"
        )
    return lines


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# PrimeVul Paired Diff Failure Analysis",
        "",
        "This report is generated from the diff-only paired eval predictions by `scripts/analyze_primevul_diff_failures.py`.",
        "",
        "## Summary",
        "",
        f"- Threshold: `{summary['threshold']:.4f}`",
        f"- Accuracy: `{summary['accuracy']:.4f}`",
        f"- Recall: `{summary['recall']:.4f}`",
        f"- Specificity: `{summary['specificity']:.4f}`",
        f"- Precision: `{summary['precision']:.4f}`",
        f"- Errors: `{summary['fp']}` false positives and `{summary['fn']}` false negatives out of `{summary['num_examples']}` examples",
        "",
        "## By CWE",
        "",
        *_table(payload["by_cwe"], "vulnerability_type"),
        "",
        "## By Project",
        "",
        *_table(payload["by_project"], "project"),
        "",
        "## By Changed-Line Bucket",
        "",
        *_table(payload["by_changed_line_bucket"], "changed_line_bucket"),
        "",
        "## By Confidence Bucket",
        "",
        *_table(payload["by_confidence_bucket"], "confidence_bucket"),
        "",
        "## Highest-Confidence False Positives",
        "",
        *_examples_table(payload["top_false_positives"]),
        "",
        "## Lowest-Probability False Negatives",
        "",
        *_examples_table(payload["top_false_negatives"]),
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze PrimeVul paired diff-only classifier failures.")
    parser.add_argument(
        "--dataset",
        default="data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl",
    )
    parser.add_argument(
        "--predictions",
        default="outputs/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_eval1800_dedup_predictions.jsonl",
    )
    parser.add_argument("--threshold", type=float, default=0.6)
    parser.add_argument("--json-output", default="reports/secure_code_primevul_pair_diff_only_failure_analysis.json")
    parser.add_argument("--md-output", default="reports/PRIMEVUL_PAIR_DIFF_FAILURE_ANALYSIS.md")
    args = parser.parse_args()

    payload = build_failure_analysis(
        read_jsonl(args.dataset),
        read_jsonl(args.predictions),
        threshold=args.threshold,
    )
    write_json(args.json_output, payload)
    md_path = Path(args.md_output)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()

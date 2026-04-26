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

from vrf.io_utils import read_json, write_json


def _metric(row: dict[str, Any], key: str) -> float:
    return float(row.get(key, 0.0))


def _from_report(label: str, path: str, *, threshold: float | None = None, note: str = "") -> dict[str, Any]:
    payload = read_json(path)
    precision = _metric(payload, "precision")
    recall = _metric(payload, "vulnerable_recall")
    f1 = _metric(payload, "f1")
    if not f1 and precision and recall:
        f1 = round((2 * precision * recall) / (precision + recall), 4)
    return {
        "system": label,
        "source": path,
        "threshold": threshold,
        "accuracy": _metric(payload, "presence_accuracy"),
        "recall": recall,
        "specificity": _metric(payload, "safe_specificity"),
        "precision": precision,
        "f1": f1,
        "balanced_accuracy": _metric(payload, "balanced_accuracy") or _metric(payload, "presence_accuracy"),
        "note": note,
    }


def _from_sweep(
    label: str,
    path: str,
    *,
    selector: str = "best_by_balanced_accuracy",
    note: str = "",
) -> dict[str, Any]:
    payload = read_json(path)
    row = payload[selector]
    return {
        "system": label,
        "source": path,
        "threshold": _metric(row, "threshold"),
        "accuracy": _metric(row, "presence_accuracy"),
        "recall": _metric(row, "vulnerable_recall"),
        "specificity": _metric(row, "safe_specificity"),
        "precision": _metric(row, "precision"),
        "f1": _metric(row, "f1"),
        "balanced_accuracy": _metric(row, "balanced_accuracy"),
        "note": note,
    }


def build_rows() -> list[dict[str, Any]]:
    return [
        _from_report(
            "same-source detector",
            "reports/secure_code_primevul_cls_qwen15bcoder_lora_presence_3000_v1_holdout2000_report.json",
            threshold=0.5,
            note="artifact-sensitive same-source holdout",
        ),
        _from_sweep(
            "same-source detector on paired eval",
            "reports/secure_code_primevul_cls_qwen15bcoder_lora_presence_3000_v1_paired1800_threshold_sweep.json",
            note="fails paired specificity",
        ),
        _from_sweep(
            "paired-trained snippet detector",
            "reports/secure_code_primevul_cls_qwen15bcoder_lora_paired_presence_3000_v1_paired1800_threshold_sweep.json",
            note="near chance on paired snippets",
        ),
        _from_sweep(
            "metadata-only control",
            "reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_metadata_only_3000_v1_eval1800_threshold_sweep.json",
            note="negative control",
        ),
        _from_sweep(
            "candidate-only control",
            "reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_candidate_only_3000_v1_eval1800_threshold_sweep.json",
            note="negative control",
        ),
        _from_sweep(
            "counterpart-only control",
            "reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_counterpart_only_3000_v1_eval1800_threshold_sweep.json",
            note="negative control",
        ),
        _from_sweep(
            "pair-context detector",
            "reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_context_3000_v1_eval1800_threshold_sweep.json",
            note="explicit comparison helps",
        ),
        _from_sweep(
            "candidate+diff detector",
            "reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_candidate_plus_diff_3000_v1_eval1800_threshold_sweep.json",
            note="extra context dilutes patch signal",
        ),
        _from_sweep(
            "diff-only detector",
            "reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_eval1800_threshold_sweep.json",
            note="best original paired formulation",
        ),
        _from_sweep(
            "diff-only detector, dedup eval",
            "reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_eval1800_dedup_threshold_sweep.json",
            note="removes 8 exact/near-duplicate eval rows",
        ),
        _from_sweep(
            "diff-only detector, seed7 dedup",
            "reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_seed7_v1_eval1792_threshold_sweep.json",
            note="multi-seed stability",
        ),
        _from_sweep(
            "diff-only detector, seed99 dedup",
            "reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_seed99_v1_eval1792_threshold_sweep.json",
            note="multi-seed stability",
        ),
    ]


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    diff_seed_rows = [
        row
        for row in rows
        if row["system"]
        in {
            "diff-only detector, dedup eval",
            "diff-only detector, seed7 dedup",
            "diff-only detector, seed99 dedup",
        }
    ]
    balanced_values = [row["balanced_accuracy"] for row in diff_seed_rows]
    return {
        "headline": "PrimeVul paired diff reasoning is the strongest current formulation.",
        "diff_seed_balanced_accuracy_mean": round(statistics.mean(balanced_values), 4),
        "diff_seed_balanced_accuracy_min": round(min(balanced_values), 4),
        "diff_seed_balanced_accuracy_max": round(max(balanced_values), 4),
        "diff_seed_balanced_accuracy_range": round(max(balanced_values) - min(balanced_values), 4),
        "negative_control_best_balanced_accuracy_max": round(
            max(
                row["balanced_accuracy"]
                for row in rows
                if row["system"] in {"metadata-only control", "candidate-only control", "counterpart-only control"}
            ),
            4,
        ),
    }


def format_value(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value:.4f}"


def render_markdown(rows: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Main Results",
        "",
        "This table is generated from run artifacts by `scripts/build_primevul_main_results.py`.",
        "",
        "## Summary",
        "",
        "![PrimeVul paired benchmark results](assets/primevul_main_results.svg)",
        "",
        f"- Headline: {summary['headline']}",
        f"- Diff-only dedup multi-seed balanced accuracy mean: `{summary['diff_seed_balanced_accuracy_mean']:.4f}`",
        f"- Diff-only dedup multi-seed range: `{summary['diff_seed_balanced_accuracy_min']:.4f}-{summary['diff_seed_balanced_accuracy_max']:.4f}`",
        f"- Strongest negative-control balanced accuracy: `{summary['negative_control_best_balanced_accuracy_max']:.4f}`",
        "",
        "## Main Table",
        "",
        "| System | Threshold | Accuracy | Recall | Specificity | Precision | F1 | Balanced Accuracy | Note |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in rows:
        threshold = "" if row["threshold"] is None else format_value(float(row["threshold"]))
        lines.append(
            "| "
            + " | ".join(
                [
                    row["system"],
                    threshold,
                    format_value(row["accuracy"]),
                    format_value(row["recall"]),
                    format_value(row["specificity"]),
                    format_value(row["precision"]),
                    format_value(row["f1"]),
                    format_value(row["balanced_accuracy"]),
                    row["note"],
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the PrimeVul main-results summary table from report artifacts.")
    parser.add_argument("--json-output", default="reports/PRIMEVUL_MAIN_RESULTS.json")
    parser.add_argument("--md-output", default="reports/PRIMEVUL_MAIN_RESULTS.md")
    args = parser.parse_args()

    rows = build_rows()
    summary = build_summary(rows)
    payload = {"summary": summary, "rows": rows}
    write_json(args.json_output, payload)
    md_path = Path(args.md_output)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(rows, summary), encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()

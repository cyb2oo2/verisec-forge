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

from scripts.evaluate_primevul_bucket_router import (
    compute_binary_metrics,
    compute_group_metrics,
    load_prediction_queues,
    render_markdown,
    route_predictions,
    summarize_by_bucket,
)
from vrf.io_utils import read_jsonl, write_json, write_jsonl


def parse_thresholds(value: str) -> list[float]:
    thresholds = [float(part.strip()) for part in value.split(",") if part.strip()]
    if not thresholds:
        raise ValueError("At least one bucket threshold is required")
    return thresholds


def split_pair_keys(rows: list[dict[str, Any]], *, calibration_fraction: float, seed: int) -> dict[str, set[str]]:
    if not 0.0 < calibration_fraction < 1.0:
        raise ValueError("calibration_fraction must be between 0 and 1")
    pair_keys = sorted({str(row.get("pair_key") or row["id"]) for row in rows})
    rng = random.Random(seed)
    rng.shuffle(pair_keys)
    calibration_count = max(1, round(len(pair_keys) * calibration_fraction))
    calibration_keys = set(pair_keys[:calibration_count])
    eval_keys = set(pair_keys[calibration_count:])
    if not eval_keys:
        raise ValueError("Calibration split consumed all pair keys")
    return {"calibration": calibration_keys, "eval": eval_keys}


def filter_by_pair_keys(rows: list[dict[str, Any]], pair_keys: set[str]) -> list[dict[str, Any]]:
    return [row for row in rows if str(row.get("pair_key") or row["id"]) in pair_keys]


def build_report_for_threshold(
    dataset_rows: list[dict[str, Any]],
    *,
    default_predictions_path: str,
    bucket_predictions_path: str,
    bucket: str,
    default_threshold: float,
    bucket_threshold: float,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    routed_rows, route_counts = route_predictions(
        dataset_rows,
        load_prediction_queues(default_predictions_path),
        load_prediction_queues(bucket_predictions_path),
        bucket=bucket,
        default_threshold=default_threshold,
        bucket_threshold=bucket_threshold,
    )
    return routed_rows, {
        "thresholds": {"default": default_threshold, "bucket": bucket_threshold},
        "route_counts": route_counts,
        "overall": compute_binary_metrics(routed_rows),
        "group_metrics": compute_group_metrics(routed_rows),
        "by_bucket": summarize_by_bucket(routed_rows),
    }


def exact_binary_metric(metrics: dict[str, Any], selector: str) -> float:
    if not {"num_examples", "tp", "tn", "fp", "fn"}.issubset(metrics):
        return float(metrics[selector])
    total = int(metrics["num_examples"])
    tp = int(metrics["tp"])
    tn = int(metrics["tn"])
    fp = int(metrics["fp"])
    fn = int(metrics["fn"])
    accuracy = (tp + tn) / total if total else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    balanced_accuracy = (recall + specificity) / 2 if total else 0.0
    values = {
        "presence_accuracy": accuracy,
        "label_accuracy": accuracy,
        "vulnerable_recall": recall,
        "safe_specificity": specificity,
        "precision": precision,
        "f1": f1,
        "balanced_accuracy": balanced_accuracy,
    }
    if selector not in values:
        raise ValueError(f"Unsupported binary metric selector: {selector}")
    return values[selector]


def select_threshold(rows: list[dict[str, Any]], *, selector: str) -> dict[str, Any]:
    if selector not in {"balanced_accuracy", "f1"}:
        raise ValueError(f"Unsupported selector: {selector}")
    selected = max(
        rows,
        key=lambda row: (
            exact_binary_metric(row["overall"], selector),
            exact_binary_metric(row["overall"], "balanced_accuracy"),
            row["bucket_threshold"],
        ),
    )
    selected["selection_scores"] = {
        "primary_metric": selector,
        "primary_score": exact_binary_metric(selected["overall"], selector),
        "secondary_metric": "balanced_accuracy",
        "secondary_score": exact_binary_metric(selected["overall"], "balanced_accuracy"),
        "tie_break": "highest_bucket_threshold",
        "tie_break_value": float(selected["bucket_threshold"]),
    }
    return selected


def render_calibrated_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Direction-Aware Bucket Router Calibration",
        "",
        "This report selects the large-diff bucket threshold on a pair-key calibration split and reports the selected router on held-out pair keys.",
        "",
        "## Protocol",
        "",
        f"- Split seed: `{report['split']['seed']}`",
        f"- Calibration fraction: `{report['split']['calibration_fraction']}`",
        f"- Calibration pair groups: `{report['split']['calibration_pair_count']}`",
        f"- Held-out eval pair groups: `{report['split']['eval_pair_count']}`",
        f"- Selector: `{report['selection']['selector']}`",
        f"- Selected bucket threshold: `{report['selection']['bucket_threshold']}`",
        f"- Tie-break policy: `{report['selection']['selection_scores']['tie_break']}`",
        f"- Selection score (unrounded): `{report['selection']['selection_scores']['primary_metric']}={report['selection']['selection_scores']['primary_score']}`",
        "",
        "## Calibration Sweep",
        "",
        "| bucket_threshold | bal_acc | recall | specificity | precision | f1 | group_all_correct | orientation |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in report["calibration_sweep"]:
        overall = row["overall"]
        group_metrics = row["group_metrics"]
        lines.append(
            "| "
            + " | ".join(
                [
                    str(row["bucket_threshold"]),
                    str(overall["balanced_accuracy"]),
                    str(overall["vulnerable_recall"]),
                    str(overall["safe_specificity"]),
                    str(overall["precision"]),
                    str(overall["f1"]),
                    str(group_metrics["group_all_correct_rate"]),
                    str(group_metrics["orientation_accuracy"]),
                ]
            )
            + " |"
        )
    lines.extend(["", "## Held-Out Eval", ""])
    eval_report = {
        "thresholds": report["selection"]["thresholds"],
        "bucket": report["bucket"],
        "route_counts": report["eval"]["route_counts"],
        "overall": report["eval"]["overall"],
        "group_metrics": report["eval"]["group_metrics"],
        "by_bucket": report["eval"]["by_bucket"],
    }
    lines.append(render_markdown(eval_report).split("\n", 1)[1].strip())
    lines.extend(
        [
            "",
            "## Same-Split Control",
            "",
            "Baseline direction-aware detector on the same held-out pair groups:",
            "",
            "| bal_acc | recall | specificity | precision | f1 | group_all_correct | orientation |",
            "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    control = report["same_split_controls"]["baseline_direction_aware"]
    lines.append(
        "| "
        + " | ".join(
            [
                str(control["overall"]["balanced_accuracy"]),
                str(control["overall"]["vulnerable_recall"]),
                str(control["overall"]["safe_specificity"]),
                str(control["overall"]["precision"]),
                str(control["overall"]["f1"]),
                str(control["group_metrics"]["group_all_correct_rate"]),
                str(control["group_metrics"]["orientation_accuracy"]),
            ]
        )
        + " |"
    )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Select a PrimeVul bucket-router threshold on a pair-key calibration split.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--default-predictions", required=True)
    parser.add_argument("--bucket-predictions", required=True)
    parser.add_argument("--bucket", default="26+")
    parser.add_argument("--default-threshold", type=float, default=0.5)
    parser.add_argument("--bucket-thresholds", default="0.5,0.6,0.7,0.8,0.9")
    parser.add_argument("--selector", default="balanced_accuracy", choices=["balanced_accuracy", "f1"])
    parser.add_argument("--calibration-fraction", type=float, default=0.3)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    parser.add_argument("--predictions-output")
    args = parser.parse_args()

    dataset_rows = read_jsonl(args.dataset)
    split = split_pair_keys(dataset_rows, calibration_fraction=args.calibration_fraction, seed=args.seed)
    calibration_rows = filter_by_pair_keys(dataset_rows, split["calibration"])
    eval_rows = filter_by_pair_keys(dataset_rows, split["eval"])

    calibration_sweep: list[dict[str, Any]] = []
    for threshold in parse_thresholds(args.bucket_thresholds):
        routed_rows, metrics = build_report_for_threshold(
            calibration_rows,
            default_predictions_path=args.default_predictions,
            bucket_predictions_path=args.bucket_predictions,
            bucket=args.bucket,
            default_threshold=args.default_threshold,
            bucket_threshold=threshold,
        )
        calibration_sweep.append(
            {
                "bucket_threshold": threshold,
                "num_predictions": len(routed_rows),
                **metrics,
            }
        )

    selected = select_threshold(calibration_sweep, selector=args.selector)
    routed_eval_rows, eval_metrics = build_report_for_threshold(
        eval_rows,
        default_predictions_path=args.default_predictions,
        bucket_predictions_path=args.bucket_predictions,
        bucket=args.bucket,
        default_threshold=args.default_threshold,
        bucket_threshold=float(selected["bucket_threshold"]),
    )
    _, baseline_eval_metrics = build_report_for_threshold(
        eval_rows,
        default_predictions_path=args.default_predictions,
        bucket_predictions_path=args.default_predictions,
        bucket=args.bucket,
        default_threshold=args.default_threshold,
        bucket_threshold=args.default_threshold,
    )
    report = {
        "dataset": args.dataset,
        "default_predictions": args.default_predictions,
        "bucket_predictions": args.bucket_predictions,
        "bucket": args.bucket,
        "split": {
            "seed": args.seed,
            "calibration_fraction": args.calibration_fraction,
            "calibration_pair_count": len(split["calibration"]),
            "eval_pair_count": len(split["eval"]),
            "calibration_rows": len(calibration_rows),
            "eval_rows": len(eval_rows),
        },
        "selection": {
            "selector": args.selector,
            "bucket_threshold": selected["bucket_threshold"],
            "selection_scores": selected["selection_scores"],
            "thresholds": {
                "default": args.default_threshold,
                "bucket": selected["bucket_threshold"],
            },
            "calibration_overall": selected["overall"],
            "calibration_group_metrics": selected["group_metrics"],
        },
        "calibration_sweep": calibration_sweep,
        "same_split_controls": {
            "baseline_direction_aware": baseline_eval_metrics,
        },
        "eval": eval_metrics,
    }
    write_json(args.json_output, report)
    if args.predictions_output:
        write_jsonl(args.predictions_output, routed_eval_rows)
    if args.md_output:
        md_path = Path(args.md_output)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(render_calibrated_markdown(report), encoding="utf-8")
    print(json.dumps({"selected": report["selection"], "eval": report["eval"]["overall"]}, indent=2))


if __name__ == "__main__":
    main()

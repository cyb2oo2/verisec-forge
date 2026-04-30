from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.build_primevul_directional_recall_recovery_dataset import changed_line_bucket
from vrf.io_utils import read_jsonl, write_json, write_jsonl


def rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)


def compute_binary_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    tp = sum(1 for row in rows if row["gold"] == 1 and row["pred"] == 1)
    tn = sum(1 for row in rows if row["gold"] == 0 and row["pred"] == 0)
    fp = sum(1 for row in rows if row["gold"] == 0 and row["pred"] == 1)
    fn = sum(1 for row in rows if row["gold"] == 1 and row["pred"] == 0)
    accuracy = (tp + tn) / total if total else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    balanced_accuracy = (recall + specificity) / 2 if total else 0.0
    return {
        "num_examples": total,
        "presence_accuracy": round(accuracy, 4),
        "label_accuracy": round(accuracy, 4),
        "vulnerable_recall": round(recall, 4),
        "safe_specificity": round(specificity, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "balanced_accuracy": round(balanced_accuracy, 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def compute_group_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("pair_key") or row["id"])].append(row)

    all_correct = 0
    orientation_correct = 0
    orientation_eligible = 0
    mixed_label_groups = 0
    for group_rows in grouped.values():
        if all(row["gold"] == row["pred"] for row in group_rows):
            all_correct += 1
        positives = [row for row in group_rows if row["gold"] == 1]
        negatives = [row for row in group_rows if row["gold"] == 0]
        if positives and negatives:
            mixed_label_groups += 1
            pos_prob = sum(float(row["vuln_probability"]) for row in positives) / len(positives)
            neg_prob = sum(float(row["vuln_probability"]) for row in negatives) / len(negatives)
            orientation_eligible += 1
            if pos_prob > neg_prob:
                orientation_correct += 1

    group_count = len(grouped)
    return {
        "unique_pair_count": group_count,
        "mixed_label_pair_count": mixed_label_groups,
        "group_all_correct": all_correct,
        "group_all_correct_rate": rate(all_correct, group_count),
        "orientation_eligible_pair_count": orientation_eligible,
        "orientation_correct": orientation_correct,
        "orientation_accuracy": rate(orientation_correct, orientation_eligible),
    }


PredictionQueues = dict[str, Deque[dict[str, Any]]]


def load_prediction_queues(path: str | Path) -> PredictionQueues:
    predictions: PredictionQueues = {}
    for row in read_jsonl(path):
        predictions.setdefault(row["id"], deque()).append(row)
    return predictions


def normalize_prediction_queues(predictions: PredictionQueues | dict[str, dict[str, Any]]) -> PredictionQueues:
    normalized: PredictionQueues = {}
    for row_id, value in predictions.items():
        if isinstance(value, deque):
            normalized[row_id] = deque(value)
        else:
            normalized[row_id] = deque([value])
    return normalized


def consume_prediction(predictions: PredictionQueues, row_id: str, *, source_name: str) -> dict[str, Any]:
    if row_id not in predictions or not predictions[row_id]:
        raise ValueError(f"Missing {source_name} prediction for id: {row_id}")
    return predictions[row_id].popleft()


def route_predictions(
    dataset_rows: list[dict[str, Any]],
    default_predictions: PredictionQueues | dict[str, dict[str, Any]],
    bucket_predictions: PredictionQueues | dict[str, dict[str, Any]],
    *,
    bucket: str,
    default_threshold: float,
    bucket_threshold: float,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    default_queues = normalize_prediction_queues(default_predictions)
    bucket_queues = normalize_prediction_queues(bucket_predictions)
    routed: list[dict[str, Any]] = []
    route_counts = {"default": 0, "bucket": 0}
    for dataset_row in dataset_rows:
        row_id = dataset_row["id"]
        default_prediction = consume_prediction(default_queues, row_id, source_name="default")
        bucket_prediction = consume_prediction(bucket_queues, row_id, source_name="bucket")

        changed_lines, changed_bucket = changed_line_bucket(
            str(dataset_row.get("pair_text") or dataset_row.get("prompt") or "")
        )
        uses_bucket_route = changed_bucket == bucket
        source = bucket_prediction if uses_bucket_route else default_prediction
        threshold = bucket_threshold if uses_bucket_route else default_threshold
        probability = float(source["vuln_probability"])
        gold = int(bool(dataset_row.get("has_vulnerability")))
        pred = int(probability >= threshold)
        route = "bucket" if uses_bucket_route else "default"
        route_counts[route] += 1
        routed.append(
            {
                "id": row_id,
                "gold": gold,
                "pred": pred,
                "vuln_probability": probability,
                "threshold": threshold,
                "route": route,
                "pair_key": dataset_row.get("pair_key") or row_id,
                "changed_lines": changed_lines,
                "changed_line_bucket": changed_bucket,
            }
        )
    return routed, route_counts


def summarize_by_bucket(rows: list[dict[str, Any]]) -> dict[str, Any]:
    buckets = sorted({str(row["changed_line_bucket"]) for row in rows})
    return {
        bucket: compute_binary_metrics([row for row in rows if row["changed_line_bucket"] == bucket])
        for bucket in buckets
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Direction-Aware Bucket Router",
        "",
        "This report routes large diff samples through the recall-recovery detector while keeping the baseline direction-aware detector for all other buckets.",
        "",
        "## Routing",
        "",
        f"- Default threshold: `{report['thresholds']['default']}`",
        f"- Bucket route: `{report['bucket']}`",
        f"- Bucket threshold: `{report['thresholds']['bucket']}`",
        f"- Default routed rows: `{report['route_counts']['default']}`",
        f"- Bucket routed rows: `{report['route_counts']['bucket']}`",
        "",
        "## Overall Metrics",
        "",
        "| metric | value |",
        "| --- | ---: |",
    ]
    for key in [
        "num_examples",
        "presence_accuracy",
        "balanced_accuracy",
        "vulnerable_recall",
        "safe_specificity",
        "precision",
        "f1",
        "tp",
        "tn",
        "fp",
        "fn",
    ]:
        lines.append(f"| {key} | {report['overall'][key]} |")

    lines.extend(
        [
            "",
            "## Pair/Group Metrics",
            "",
            "| metric | value |",
            "| --- | ---: |",
        ]
    )
    for key in [
        "unique_pair_count",
        "mixed_label_pair_count",
        "group_all_correct",
        "group_all_correct_rate",
        "orientation_eligible_pair_count",
        "orientation_correct",
        "orientation_accuracy",
    ]:
        lines.append(f"| {key} | {report['group_metrics'][key]} |")

    lines.extend(
        [
            "",
            "## Bucket Metrics",
            "",
            "| bucket | n | bal_acc | recall | specificity | precision | f1 | tp | tn | fp | fn |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for bucket, metrics in report["by_bucket"].items():
        lines.append(
            "| "
            + " | ".join(
                [
                    bucket,
                    str(metrics["num_examples"]),
                    str(metrics["balanced_accuracy"]),
                    str(metrics["vulnerable_recall"]),
                    str(metrics["safe_specificity"]),
                    str(metrics["precision"]),
                    str(metrics["f1"]),
                    str(metrics["tp"]),
                    str(metrics["tn"]),
                    str(metrics["fp"]),
                    str(metrics["fn"]),
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a PrimeVul changed-line-bucket prediction router.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--default-predictions", required=True)
    parser.add_argument("--bucket-predictions", required=True)
    parser.add_argument("--bucket", default="26+")
    parser.add_argument("--default-threshold", type=float, default=0.5)
    parser.add_argument("--bucket-threshold", type=float, default=0.8)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    parser.add_argument("--predictions-output")
    args = parser.parse_args()

    routed_rows, route_counts = route_predictions(
        read_jsonl(args.dataset),
        load_prediction_queues(args.default_predictions),
        load_prediction_queues(args.bucket_predictions),
        bucket=args.bucket,
        default_threshold=args.default_threshold,
        bucket_threshold=args.bucket_threshold,
    )
    report = {
        "dataset": args.dataset,
        "default_predictions": args.default_predictions,
        "bucket_predictions": args.bucket_predictions,
        "bucket": args.bucket,
        "thresholds": {
            "default": args.default_threshold,
            "bucket": args.bucket_threshold,
        },
        "route_counts": route_counts,
        "overall": compute_binary_metrics(routed_rows),
        "group_metrics": compute_group_metrics(routed_rows),
        "by_bucket": summarize_by_bucket(routed_rows),
    }
    write_json(args.json_output, report)
    if args.predictions_output:
        write_jsonl(args.predictions_output, routed_rows)
    if args.md_output:
        md_path = Path(args.md_output)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(report["overall"], indent=2))


if __name__ == "__main__":
    main()

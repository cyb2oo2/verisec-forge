from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median
from typing import Any

from vrf.io_utils import read_jsonl, write_json


def binary_metrics(rows: list[dict[str, Any]], predictions: dict[str, bool]) -> dict[str, Any]:
    tp = tn = fp = fn = 0
    for row in rows:
        gold = bool(row.get("has_vulnerability"))
        pred = bool(predictions[str(row["id"])])
        if pred and gold:
            tp += 1
        elif pred and not gold:
            fp += 1
        elif (not pred) and gold:
            fn += 1
        else:
            tn += 1
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {
        "accuracy": round(accuracy, 4),
        "recall": round(recall, 4),
        "specificity": round(specificity, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def best_length_threshold(train_rows: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = sorted({len(str(row.get("code") or "")) for row in train_rows})
    best: dict[str, Any] | None = None
    for threshold in candidates:
        for direction in ["ge", "lt"]:
            predictions = {
                str(row["id"]): (len(str(row.get("code") or "")) >= threshold)
                if direction == "ge"
                else (len(str(row.get("code") or "")) < threshold)
                for row in train_rows
            }
            metrics = binary_metrics(train_rows, predictions)
            candidate = {"threshold": threshold, "direction": direction, **metrics}
            if best is None or (candidate["accuracy"], candidate["f1"]) > (best["accuracy"], best["f1"]):
                best = candidate
    return best or {"threshold": 0, "direction": "ge"}


def apply_length_threshold(rows: list[dict[str, Any]], *, threshold: int, direction: str) -> dict[str, bool]:
    return {
        str(row["id"]): (len(str(row.get("code") or "")) >= threshold)
        if direction == "ge"
        else (len(str(row.get("code") or "")) < threshold)
        for row in rows
    }


def majority_by_field(train_rows: list[dict[str, Any]], eval_rows: list[dict[str, Any]], field: str) -> dict[str, Any]:
    grouped: defaultdict[str, Counter[bool]] = defaultdict(Counter)
    global_counts: Counter[bool] = Counter()
    for row in train_rows:
        label = bool(row.get("has_vulnerability"))
        value = str(row.get(field) or "unknown")
        grouped[value][label] += 1
        global_counts[label] += 1

    global_majority = global_counts[True] >= global_counts[False]
    mapping = {
        value: counts[True] >= counts[False]
        for value, counts in grouped.items()
    }
    predictions = {
        str(row["id"]): mapping.get(str(row.get(field) or "unknown"), global_majority)
        for row in eval_rows
    }
    coverage = sum(1 for row in eval_rows if str(row.get(field) or "unknown") in mapping)
    return {
        "field": field,
        "known_value_coverage": round(coverage / len(eval_rows), 4) if eval_rows else 0.0,
        **binary_metrics(eval_rows, predictions),
    }


def label_distribution(rows: list[dict[str, Any]]) -> dict[str, Any]:
    lengths_by_label = {
        "vulnerable": [len(str(row.get("code") or "")) for row in rows if bool(row.get("has_vulnerability"))],
        "safe": [len(str(row.get("code") or "")) for row in rows if not bool(row.get("has_vulnerability"))],
    }
    payload: dict[str, Any] = {}
    for label, lengths in lengths_by_label.items():
        payload[label] = {
            "count": len(lengths),
            "median_code_chars": median(lengths) if lengths else 0,
            "p90_code_chars": sorted(lengths)[int(0.9 * (len(lengths) - 1))] if lengths else 0,
        }
    return payload


def detector_metrics(eval_rows: list[dict[str, Any]], probability_path: str | None, threshold: float) -> dict[str, Any] | None:
    if not probability_path:
        return None
    probability_rows = {str(row["id"]): row for row in read_jsonl(probability_path)}
    predictions = {
        str(row["id"]): float(probability_rows[str(row["id"])]["vuln_probability"]) >= threshold
        for row in eval_rows
        if str(row["id"]) in probability_rows
    }
    rows = [row for row in eval_rows if str(row["id"]) in predictions]
    return binary_metrics(rows, predictions)


def main() -> None:
    parser = argparse.ArgumentParser(description="Diagnose shortcut baselines for PrimeVul-style presence detection.")
    parser.add_argument("--train", required=True, help="Training JSONL used to fit shortcut baselines")
    parser.add_argument("--eval", required=True, help="Evaluation JSONL")
    parser.add_argument("--output", required=True, help="Output JSON report")
    parser.add_argument("--probabilities", default="", help="Optional detector probability JSONL")
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()

    train_rows = read_jsonl(args.train)
    eval_rows = read_jsonl(args.eval)
    length_rule = best_length_threshold(train_rows)
    length_predictions = apply_length_threshold(
        eval_rows,
        threshold=int(length_rule["threshold"]),
        direction=str(length_rule["direction"]),
    )

    fields = ["project", "vulnerability_type", "cve", "file_name"]
    payload = {
        "train_path": args.train,
        "eval_path": args.eval,
        "train_distribution": label_distribution(train_rows),
        "eval_distribution": label_distribution(eval_rows),
        "length_threshold_baseline": {
            "fit_on_train": length_rule,
            "eval": binary_metrics(eval_rows, length_predictions),
        },
        "field_majority_baselines": [
            majority_by_field(train_rows, eval_rows, field)
            for field in fields
            if any(row.get(field) not in {None, "", "unknown"} for row in train_rows + eval_rows)
        ],
        "detector": detector_metrics(eval_rows, args.probabilities or None, args.threshold),
    }
    write_json(args.output, payload)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()

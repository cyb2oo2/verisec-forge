from __future__ import annotations

import argparse
import json
import math
import random
import re
import statistics
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from vrf.io_utils import read_jsonl, write_json


TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}|\d+")


def split_rows(rows: list[dict[str, Any]], *, calibration_fraction: float, seed: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ordered = sorted(rows, key=lambda row: str(row["pair_key"]))
    rng = random.Random(seed)
    shuffled = list(ordered)
    rng.shuffle(shuffled)
    calibration_count = int(round(len(shuffled) * calibration_fraction))
    return shuffled[:calibration_count], shuffled[calibration_count:]


def safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def side_window_features(row: dict[str, Any], side: str) -> dict[str, float]:
    windows = row.get(f"side_{side}_windows", [])
    labels = [label for window in windows for label in window.get("direction_labels", [])]
    risk_values = [safe_float(window.get("risk_support")) for window in windows]
    safety_values = [safe_float(window.get("safety_support")) for window in windows]
    protection_values = [safe_float(window.get("protection_delta")) for window in windows]
    return {
        f"{side}_risk_max": max(risk_values) if risk_values else 0.0,
        f"{side}_risk_sum": sum(risk_values),
        f"{side}_safety_max": max(safety_values) if safety_values else 0.0,
        f"{side}_safety_sum": sum(safety_values),
        f"{side}_protection_delta_sum": sum(protection_values),
        f"{side}_candidate_adds_protection": float(labels.count("candidate_adds_protection")),
        f"{side}_candidate_removes_protection": float(labels.count("candidate_removes_protection")),
        f"{side}_candidate_introduces_risk": float(labels.count("candidate_introduces_risk")),
        f"{side}_candidate_removes_risk": float(labels.count("candidate_removes_risk")),
    }


def add_numeric(features: dict[str, float], name: str, value: float) -> None:
    features[name] = value


def add_tokens(features: dict[str, float], prefix: str, values: list[str], *, weight: float = 1.0) -> None:
    for value in values:
        for token in TOKEN_RE.findall(value.lower()):
            features[f"{prefix}:{token}"] = features.get(f"{prefix}:{token}", 0.0) + weight


def window_text_fields(windows: list[dict[str, Any]], field: str) -> list[str]:
    values: list[str] = []
    for window in windows:
        raw = window.get(field)
        if isinstance(raw, list):
            values.extend(str(item) for item in raw)
        elif raw:
            values.append(str(raw))
    return values


def row_features(row: dict[str, Any]) -> dict[str, float]:
    features: dict[str, float] = {"bias": 1.0}
    side_a = side_window_features(row, "a")
    side_b = side_window_features(row, "b")
    features.update(side_a)
    features.update(side_b)
    add_numeric(features, "probability_gap", safe_float(row.get("probability_gap")))
    add_numeric(features, "side_a_probability", safe_float(row.get("side_a_probability")))
    add_numeric(features, "side_b_probability", safe_float(row.get("side_b_probability")))
    for name in [
        "risk_max",
        "risk_sum",
        "safety_max",
        "safety_sum",
        "protection_delta_sum",
        "candidate_adds_protection",
        "candidate_removes_protection",
        "candidate_introduces_risk",
        "candidate_removes_risk",
    ]:
        add_numeric(features, f"margin_{name}", side_a[f"a_{name}"] - side_b[f"b_{name}"])

    a_windows = row.get("side_a_windows", [])
    b_windows = row.get("side_b_windows", [])
    add_tokens(features, "a_removed", window_text_fields(a_windows, "removed_preview"))
    add_tokens(features, "a_added", window_text_fields(a_windows, "added_preview"))
    add_tokens(features, "b_removed", window_text_fields(b_windows, "removed_preview"))
    add_tokens(features, "b_added", window_text_fields(b_windows, "added_preview"))
    add_tokens(features, "a_header", window_text_fields(a_windows, "header"), weight=0.25)
    add_tokens(features, "b_header", window_text_fields(b_windows, "header"), weight=0.25)
    return features


def label(row: dict[str, Any]) -> int:
    return int(row["label"] == "B")


def sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def dot(weights: dict[str, float], features: dict[str, float]) -> float:
    return sum(weights.get(name, 0.0) * value for name, value in features.items())


def train(
    rows: list[dict[str, Any]],
    *,
    epochs: int,
    learning_rate: float,
    l2: float,
    seed: int,
    positive_weight: float,
) -> dict[str, float]:
    rng = random.Random(seed)
    weights: dict[str, float] = {}
    train_rows = list(rows)
    for _epoch in range(epochs):
        rng.shuffle(train_rows)
        for row in train_rows:
            features = row_features(row)
            y = float(label(row))
            prediction = sigmoid(dot(weights, features))
            sample_weight = positive_weight if y == 1.0 else 1.0
            error = (prediction - y) * sample_weight
            for name, value in features.items():
                weights[name] = weights.get(name, 0.0) - learning_rate * (error * value + l2 * weights.get(name, 0.0))
    return weights


def score_rows(rows: list[dict[str, Any]], weights: dict[str, float]) -> list[dict[str, Any]]:
    scored = []
    for row in rows:
        probability = sigmoid(dot(weights, row_features(row)))
        scored.append(
            {
                "pair_key": row["pair_key"],
                "gold_invert": label(row),
                "inversion_probability": probability,
            }
        )
    return scored


def metric_for_threshold(scored: list[dict[str, Any]], threshold: float) -> dict[str, Any]:
    tp = tn = fp = fn = 0
    for row in scored:
        pred = int(float(row["inversion_probability"]) >= threshold)
        gold = int(row["gold_invert"])
        if pred == 1 and gold == 1:
            tp += 1
        elif pred == 0 and gold == 0:
            tn += 1
        elif pred == 1 and gold == 0:
            fp += 1
        else:
            fn += 1
    total = tp + tn + fp + fn
    recall_b = tp / (tp + fn) if tp + fn else 0.0
    specificity_a = tn / (tn + fp) if tn + fp else 0.0
    precision_b = tp / (tp + fp) if tp + fp else 0.0
    return {
        "threshold": threshold,
        "accuracy": round((tp + tn) / total, 4) if total else 0.0,
        "balanced_accuracy": round((recall_b + specificity_a) / 2, 4),
        "label_b_recall": round(recall_b, 4),
        "label_a_specificity": round(specificity_a, 4),
        "label_b_precision": round(precision_b, 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "flipped_pairs": tp + fp,
    }


def select_threshold(scored: list[dict[str, Any]], thresholds: list[float], selector: str) -> dict[str, Any]:
    sweep = [metric_for_threshold(scored, threshold) for threshold in thresholds]
    if selector == "balanced_accuracy":
        selected = max(sweep, key=lambda row: (row["balanced_accuracy"], row["accuracy"], -row["threshold"]))
    elif selector == "label_b_recall":
        selected = max(sweep, key=lambda row: (row["label_b_recall"], row["balanced_accuracy"], -row["threshold"]))
    else:
        raise ValueError(f"Unsupported selector: {selector}")
    return {"selected": selected, "sweep": sweep}


def compact_report(seed: int, selected: dict[str, Any], eval_metric: dict[str, Any]) -> dict[str, Any]:
    return {
        "seed": seed,
        "selected_threshold": selected["threshold"],
        "eval_accuracy": eval_metric["accuracy"],
        "eval_balanced_accuracy": eval_metric["balanced_accuracy"],
        "eval_label_b_recall": eval_metric["label_b_recall"],
        "eval_label_a_specificity": eval_metric["label_a_specificity"],
        "eval_label_b_precision": eval_metric["label_b_precision"],
        "flipped_pairs": eval_metric["flipped_pairs"],
        "tp": eval_metric["tp"],
        "tn": eval_metric["tn"],
        "fp": eval_metric["fp"],
        "fn": eval_metric["fn"],
    }


def mean(values: list[float]) -> float:
    return round(statistics.mean(values), 4) if values else 0.0


def stdev(values: list[float]) -> float:
    return round(statistics.stdev(values), 4) if len(values) > 1 else 0.0


def summarize(seed_reports: list[dict[str, Any]], baseline: dict[str, Any]) -> dict[str, Any]:
    balanced = [row["eval_balanced_accuracy"] for row in seed_reports]
    accuracy = [row["eval_accuracy"] for row in seed_reports]
    deltas = [round(row["eval_balanced_accuracy"] - baseline["balanced_accuracy"], 4) for row in seed_reports]
    return {
        "seeds": len(seed_reports),
        "baseline_always_a": baseline,
        "eval_accuracy": {"mean": mean(accuracy), "stdev": stdev(accuracy), "min": min(accuracy), "max": max(accuracy)},
        "eval_balanced_accuracy": {"mean": mean(balanced), "stdev": stdev(balanced), "min": min(balanced), "max": max(balanced)},
        "balanced_accuracy_delta_vs_always_a": {
            "mean": mean(deltas),
            "stdev": stdev(deltas),
            "min": min(deltas),
            "max": max(deltas),
            "positive_splits": sum(1 for value in deltas if value > 0),
            "negative_splits": sum(1 for value in deltas if value < 0),
        },
        "label_b_recall": {
            "mean": mean([row["eval_label_b_recall"] for row in seed_reports]),
            "min": min(row["eval_label_b_recall"] for row in seed_reports),
            "max": max(row["eval_label_b_recall"] for row in seed_reports),
        },
        "flipped_pairs": {
            "mean": mean([float(row["flipped_pairs"]) for row in seed_reports]),
            "min": min(row["flipped_pairs"] for row in seed_reports),
            "max": max(row["flipped_pairs"] for row in seed_reports),
        },
    }


def baseline_metric(rows: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [{"gold_invert": label(row), "inversion_probability": 0.0} for row in rows]
    return metric_for_threshold(scored, threshold=0.5)


def build_report(
    rows: list[dict[str, Any]],
    *,
    seeds: list[int],
    calibration_fraction: float,
    epochs: int,
    learning_rate: float,
    l2: float,
    positive_weight: float,
    thresholds: list[float],
    selector: str,
) -> dict[str, Any]:
    seed_reports = []
    for seed in seeds:
        train_rows, eval_rows = split_rows(rows, calibration_fraction=calibration_fraction, seed=seed)
        weights = train(
            train_rows,
            epochs=epochs,
            learning_rate=learning_rate,
            l2=l2,
            seed=seed,
            positive_weight=positive_weight,
        )
        calibration_scores = score_rows(train_rows, weights)
        eval_scores = score_rows(eval_rows, weights)
        selected = select_threshold(calibration_scores, thresholds, selector)["selected"]
        eval_metric = metric_for_threshold(eval_scores, float(selected["threshold"]))
        seed_reports.append(compact_report(seed, selected, eval_metric))
    baseline = baseline_metric(rows)
    return {
        "config": {
            "seeds": seeds,
            "calibration_fraction": calibration_fraction,
            "epochs": epochs,
            "learning_rate": learning_rate,
            "l2": l2,
            "positive_weight": positive_weight,
            "thresholds": thresholds,
            "selector": selector,
        },
        "summary": summarize(seed_reports, baseline),
        "seed_reports": seed_reports,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# PrimeVul Paired-Window Side Model",
        "",
        "This report evaluates a dependency-free paired-window side model over the generated `A/B` contrastive examples. `Side A` is the current high-probability side, so predicting `B` means the model recommends flipping the pair orientation.",
        "",
        "## Summary",
        "",
        f"- Seeds: `{payload['config']['seeds']}`",
        f"- Always-A baseline accuracy: `{summary['baseline_always_a']['accuracy']}`",
        f"- Always-A baseline balanced accuracy: `{summary['baseline_always_a']['balanced_accuracy']}`",
        f"- Eval accuracy mean: `{summary['eval_accuracy']['mean']}`",
        f"- Eval balanced accuracy mean: `{summary['eval_balanced_accuracy']['mean']}`",
        f"- Balanced delta vs always-A mean: `{summary['balanced_accuracy_delta_vs_always_a']['mean']}`",
        f"- Label-B recall mean: `{summary['label_b_recall']['mean']}`",
        f"- Flipped pairs mean: `{summary['flipped_pairs']['mean']}`",
        "",
        "## Per-Seed Results",
        "",
        "| seed | threshold | acc | bal_acc | label_b_recall | label_a_specificity | label_b_precision | flipped | tp | tn | fp | fn |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in payload["seed_reports"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    str(row["seed"]),
                    str(row["selected_threshold"]),
                    str(row["eval_accuracy"]),
                    str(row["eval_balanced_accuracy"]),
                    str(row["eval_label_b_recall"]),
                    str(row["eval_label_a_specificity"]),
                    str(row["eval_label_b_precision"]),
                    str(row["flipped_pairs"]),
                    str(row["tp"]),
                    str(row["tn"]),
                    str(row["fp"]),
                    str(row["fn"]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "This is a cheap signal check before any GPU model training. A useful result must beat the always-trust-high-probability baseline on held-out pair-key splits, especially on balanced accuracy and label-B recall. If it stays flat, the next step should be a stronger supervised contrastive model or better evidence targets rather than another hand-crafted gate.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_ints(value: str) -> list[int]:
    parsed = [int(part.strip()) for part in value.split(",") if part.strip()]
    if not parsed:
        raise ValueError("At least one seed is required")
    return parsed


def parse_floats(value: str) -> list[float]:
    parsed = [float(part.strip()) for part in value.split(",") if part.strip()]
    if not parsed:
        raise ValueError("At least one threshold is required")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a paired-window side model on PrimeVul contrastive examples.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--seeds", default="7,13,42,99,123")
    parser.add_argument("--calibration-fraction", type=float, default=0.3)
    parser.add_argument("--epochs", type=int, default=80)
    parser.add_argument("--learning-rate", type=float, default=0.01)
    parser.add_argument("--l2", type=float, default=0.0001)
    parser.add_argument("--positive-weight", type=float, default=4.0)
    parser.add_argument("--thresholds", default="0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9")
    parser.add_argument("--selector", default="balanced_accuracy", choices=["balanced_accuracy", "label_b_recall"])
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    args = parser.parse_args()

    payload = build_report(
        read_jsonl(args.input),
        seeds=parse_ints(args.seeds),
        calibration_fraction=args.calibration_fraction,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        l2=args.l2,
        positive_weight=args.positive_weight,
        thresholds=parse_floats(args.thresholds),
        selector=args.selector,
    )
    write_json(args.json_output, payload)
    if args.md_output:
        output = Path(args.md_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()

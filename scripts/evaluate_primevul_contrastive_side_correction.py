from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.evaluate_primevul_bucket_router import compute_binary_metrics, compute_group_metrics
from scripts.evaluate_primevul_pair_coupled_router import group_rows
from scripts.evaluate_primevul_pair_side_correction import (
    apply_gate,
    filter_by_pair_keys,
    parse_floats,
    report_for_rows,
    select_threshold,
    sigmoid,
    split_pair_keys,
)
from vrf.io_utils import read_jsonl, write_json, write_jsonl


FEATURE_NAMES = [
    "bias",
    "gap",
    "gap_squared",
    "top_probability",
    "second_probability",
    "top_risk_max",
    "top_safety_max",
    "top_risk_minus_safety",
    "top_protection_delta_max",
    "top_risk_delta_max",
    "top_candidate_adds_protection",
    "top_candidate_removes_protection",
    "top_candidate_introduces_risk",
    "top_candidate_removes_risk",
    "second_risk_max",
    "second_safety_max",
    "second_risk_minus_safety",
    "second_protection_delta_max",
    "second_risk_delta_max",
    "second_candidate_adds_protection",
    "second_candidate_removes_protection",
    "second_candidate_introduces_risk",
    "second_candidate_removes_risk",
    "risk_margin_top_minus_second",
    "safety_margin_top_minus_second",
    "protection_margin_top_minus_second",
    "risk_delta_margin_top_minus_second",
]


def hunk_groups(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row["source_id"])].append(row)
    return grouped


def source_hunk_features(rows: list[dict[str, Any]]) -> dict[str, float]:
    if not rows:
        return {
            "risk_max": 0.0,
            "safety_max": 0.0,
            "risk_minus_safety": 0.0,
            "protection_delta_max": 0.0,
            "risk_delta_max": 0.0,
            "candidate_adds_protection": 0.0,
            "candidate_removes_protection": 0.0,
            "candidate_introduces_risk": 0.0,
            "candidate_removes_risk": 0.0,
        }
    labels = [label for row in rows for label in row.get("direction_labels", [])]
    risk_max = max(float(row.get("risk_support") or 0.0) for row in rows)
    safety_max = max(float(row.get("safety_support") or 0.0) for row in rows)
    return {
        "risk_max": risk_max,
        "safety_max": safety_max,
        "risk_minus_safety": risk_max - safety_max,
        "protection_delta_max": max(float(row.get("protection_delta") or 0.0) for row in rows),
        "risk_delta_max": max(float(row.get("risk_delta") or 0.0) for row in rows),
        "candidate_adds_protection": float(labels.count("candidate_adds_protection")),
        "candidate_removes_protection": float(labels.count("candidate_removes_protection")),
        "candidate_introduces_risk": float(labels.count("candidate_introduces_risk")),
        "candidate_removes_risk": float(labels.count("candidate_removes_risk")),
    }


def group_features(group: list[dict[str, Any]], hunks_by_source: dict[str, list[dict[str, Any]]]) -> dict[str, float]:
    ordered = sorted(group, key=lambda row: float(row["vuln_probability"]), reverse=True)
    top = ordered[0]
    second = ordered[1] if len(ordered) > 1 else ordered[0]
    top_probability = float(top["vuln_probability"])
    second_probability = float(second["vuln_probability"])
    gap = top_probability - second_probability
    top_features = source_hunk_features(hunks_by_source.get(str(top["id"]), []))
    second_features = source_hunk_features(hunks_by_source.get(str(second["id"]), []))
    values = {
        "bias": 1.0,
        "gap": gap,
        "gap_squared": gap * gap,
        "top_probability": top_probability,
        "second_probability": second_probability,
    }
    for prefix, feature_values in [("top", top_features), ("second", second_features)]:
        for name, value in feature_values.items():
            values[f"{prefix}_{name}"] = value
    values.update(
        {
            "risk_margin_top_minus_second": top_features["risk_max"] - second_features["risk_max"],
            "safety_margin_top_minus_second": top_features["safety_max"] - second_features["safety_max"],
            "protection_margin_top_minus_second": top_features["protection_delta_max"] - second_features["protection_delta_max"],
            "risk_delta_margin_top_minus_second": top_features["risk_delta_max"] - second_features["risk_delta_max"],
        }
    )
    return values


def orientation_wrong(group: list[dict[str, Any]]) -> int:
    ordered = sorted(group, key=lambda row: float(row["vuln_probability"]), reverse=True)
    return int(int(ordered[0]["gold"]) != 1)


def dot(weights: dict[str, float], values: dict[str, float]) -> float:
    return sum(weights.get(name, 0.0) * values.get(name, 0.0) for name in FEATURE_NAMES)


def train_gate(
    groups: list[list[dict[str, Any]]],
    hunks_by_source: dict[str, list[dict[str, Any]]],
    *,
    epochs: int,
    learning_rate: float,
    l2: float,
    seed: int,
) -> dict[str, float]:
    rng = random.Random(seed)
    weights = {name: 0.0 for name in FEATURE_NAMES}
    train_groups = list(groups)
    for _epoch in range(epochs):
        rng.shuffle(train_groups)
        for group in train_groups:
            label = float(orientation_wrong(group))
            values = group_features(group, hunks_by_source)
            prediction = sigmoid(dot(weights, values))
            error = prediction - label
            for name in FEATURE_NAMES:
                weights[name] -= learning_rate * (error * values.get(name, 0.0) + l2 * weights[name])
    return weights


def score_groups(
    groups: list[list[dict[str, Any]]],
    hunks_by_source: dict[str, list[dict[str, Any]]],
    weights: dict[str, float],
) -> list[dict[str, Any]]:
    scored = []
    for group in groups:
        values = group_features(group, hunks_by_source)
        scored.append(
            {
                "pair_key": str(group[0].get("pair_key") or group[0]["id"]),
                "orientation_wrong": orientation_wrong(group),
                "inversion_probability": sigmoid(dot(weights, values)),
                "features": values,
            }
        )
    return scored


def build_single_split_report(
    prediction_rows: list[dict[str, Any]],
    hunk_rows: list[dict[str, Any]],
    *,
    calibration_fraction: float,
    seed: int,
    epochs: int,
    learning_rate: float,
    l2: float,
    thresholds: list[float],
    selector: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    hunks_by_source = hunk_groups(hunk_rows)
    split = split_pair_keys(prediction_rows, calibration_fraction=calibration_fraction, seed=seed)
    calibration_rows = filter_by_pair_keys(prediction_rows, split["calibration"])
    eval_rows = filter_by_pair_keys(prediction_rows, split["eval"])
    calibration_groups = list(group_rows(calibration_rows).values())
    eval_groups = list(group_rows(eval_rows).values())
    weights = train_gate(calibration_groups, hunks_by_source, epochs=epochs, learning_rate=learning_rate, l2=l2, seed=seed)
    calibration_scores = score_groups(calibration_groups, hunks_by_source, weights)
    eval_scores = score_groups(eval_groups, hunks_by_source, weights)
    selected = select_threshold(calibration_rows, calibration_scores, thresholds=thresholds, selector=selector)
    eval_score_by_pair = {row["pair_key"]: row for row in eval_scores}
    corrected_eval_rows, gate_counts = apply_gate(eval_rows, eval_score_by_pair, threshold=float(selected["selected"]["threshold"]))
    report = {
        "config": {
            "calibration_fraction": calibration_fraction,
            "seed": seed,
            "epochs": epochs,
            "learning_rate": learning_rate,
            "l2": l2,
            "thresholds": thresholds,
            "selector": selector,
        },
        "split": {
            "calibration_pair_count": len(split["calibration"]),
            "eval_pair_count": len(split["eval"]),
            "calibration_rows": len(calibration_rows),
            "eval_rows": len(eval_rows),
        },
        "weights": {name: round(value, 6) for name, value in weights.items()},
        "weights_ranked": [
            [name, round(value, 6)]
            for name, value in sorted(weights.items(), key=lambda item: abs(item[1]), reverse=True)
        ],
        "calibration": {
            "baseline": report_for_rows(calibration_rows),
            "selection": selected["selected"],
            "sweep": selected["sweep"],
        },
        "eval": {
            "baseline_pair_coupled": report_for_rows(eval_rows),
            "corrected": {**report_for_rows(corrected_eval_rows), "gate_counts": gate_counts},
        },
    }
    return report, corrected_eval_rows


def compact_report(seed: int, report: dict[str, Any]) -> dict[str, Any]:
    baseline = report["eval"]["baseline_pair_coupled"]
    corrected = report["eval"]["corrected"]
    return {
        "seed": seed,
        "selected_threshold": report["calibration"]["selection"]["threshold"],
        "baseline_balanced_accuracy": baseline["overall"]["balanced_accuracy"],
        "corrected_balanced_accuracy": corrected["overall"]["balanced_accuracy"],
        "baseline_group_all_correct_rate": baseline["group_metrics"]["group_all_correct_rate"],
        "corrected_group_all_correct_rate": corrected["group_metrics"]["group_all_correct_rate"],
        "baseline_orientation_accuracy": baseline["group_metrics"]["orientation_accuracy"],
        "corrected_orientation_accuracy": corrected["group_metrics"]["orientation_accuracy"],
        "gated_groups": corrected["gate_counts"]["gated_groups"],
        "fp_delta": corrected["overall"]["fp"] - baseline["overall"]["fp"],
        "fn_delta": corrected["overall"]["fn"] - baseline["overall"]["fn"],
    }


def metric_delta(row: dict[str, Any], metric: str) -> float:
    return round(row[f"corrected_{metric}"] - row[f"baseline_{metric}"], 4)


def mean(values: list[float]) -> float:
    return round(statistics.mean(values), 4) if values else 0.0


def stdev(values: list[float]) -> float:
    return round(statistics.stdev(values), 4) if len(values) > 1 else 0.0


def summarize(seed_reports: list[dict[str, Any]]) -> dict[str, Any]:
    balanced_deltas = [metric_delta(row, "balanced_accuracy") for row in seed_reports]
    group_deltas = [metric_delta(row, "group_all_correct_rate") for row in seed_reports]
    return {
        "seeds": len(seed_reports),
        "balanced_accuracy_delta": {
            "mean": mean(balanced_deltas),
            "stdev": stdev(balanced_deltas),
            "min": min(balanced_deltas) if balanced_deltas else 0.0,
            "max": max(balanced_deltas) if balanced_deltas else 0.0,
            "positive_splits": sum(1 for value in balanced_deltas if value > 0),
            "negative_splits": sum(1 for value in balanced_deltas if value < 0),
        },
        "group_all_correct_delta": {
            "mean": mean(group_deltas),
            "stdev": stdev(group_deltas),
            "min": min(group_deltas) if group_deltas else 0.0,
            "max": max(group_deltas) if group_deltas else 0.0,
            "positive_splits": sum(1 for value in group_deltas if value > 0),
            "negative_splits": sum(1 for value in group_deltas if value < 0),
        },
        "gated_groups": {
            "mean": mean([float(row["gated_groups"]) for row in seed_reports]),
            "min": min(row["gated_groups"] for row in seed_reports) if seed_reports else 0,
            "max": max(row["gated_groups"] for row in seed_reports) if seed_reports else 0,
        },
    }


def build_multisplit_report(
    prediction_rows: list[dict[str, Any]],
    hunk_rows: list[dict[str, Any]],
    *,
    seeds: list[int],
    calibration_fraction: float,
    epochs: int,
    learning_rate: float,
    l2: float,
    thresholds: list[float],
    selector: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    seed_reports = []
    seed42_predictions: list[dict[str, Any]] = []
    for seed in seeds:
        report, corrected_rows = build_single_split_report(
            prediction_rows,
            hunk_rows,
            calibration_fraction=calibration_fraction,
            seed=seed,
            epochs=epochs,
            learning_rate=learning_rate,
            l2=l2,
            thresholds=thresholds,
            selector=selector,
        )
        seed_reports.append(compact_report(seed, report))
        if seed == 42:
            seed42_predictions = corrected_rows
    payload = {
        "config": {
            "seeds": seeds,
            "calibration_fraction": calibration_fraction,
            "epochs": epochs,
            "learning_rate": learning_rate,
            "l2": l2,
            "thresholds": thresholds,
            "selector": selector,
        },
        "summary": summarize(seed_reports),
        "seed_reports": seed_reports,
    }
    return payload, seed42_predictions


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# PrimeVul Contrastive Side-Correction",
        "",
        "This report augments the shallow pair-side correction gate with contrastive hunk/window features from the high-probability and low-probability sides of each pair. It checks whether pseudo-evidence signals are enough to correct confident side inversions.",
        "",
        "## Summary",
        "",
        f"- Seeds: `{payload['config']['seeds']}`",
        f"- Balanced accuracy delta mean: `{summary['balanced_accuracy_delta']['mean']}`",
        f"- Balanced accuracy delta range: `{summary['balanced_accuracy_delta']['min']}` to `{summary['balanced_accuracy_delta']['max']}`",
        f"- Group all-correct delta mean: `{summary['group_all_correct_delta']['mean']}`",
        f"- Gated groups mean: `{summary['gated_groups']['mean']}`",
        "",
        "## Per-Seed Results",
        "",
        "| seed | threshold | base_bal | corr_bal | bal_delta | base_group | corr_group | group_delta | gated_groups | fp_delta | fn_delta |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in payload["seed_reports"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    str(row["seed"]),
                    str(row["selected_threshold"]),
                    str(row["baseline_balanced_accuracy"]),
                    str(row["corrected_balanced_accuracy"]),
                    str(metric_delta(row, "balanced_accuracy")),
                    str(row["baseline_group_all_correct_rate"]),
                    str(row["corrected_group_all_correct_rate"]),
                    str(metric_delta(row, "group_all_correct_rate")),
                    str(row["gated_groups"]),
                    str(row["fp_delta"]),
                    str(row["fn_delta"]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "If this remains flat, then pseudo-evidence aggregates are still too weak for a reliable correction layer. The next step should be explicit contrastive model training on paired windows, not more hand-built gate features.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_ints(value: str) -> list[int]:
    parsed = [int(part.strip()) for part in value.split(",") if part.strip()]
    if not parsed:
        raise ValueError("At least one seed is required")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate contrastive pseudo-evidence features for pair-side correction.")
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--hunk-candidates", required=True)
    parser.add_argument("--seeds", default="7,13,42,99,123")
    parser.add_argument("--calibration-fraction", type=float, default=0.3)
    parser.add_argument("--epochs", type=int, default=80)
    parser.add_argument("--learning-rate", type=float, default=0.01)
    parser.add_argument("--l2", type=float, default=0.0001)
    parser.add_argument("--thresholds", default="0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9")
    parser.add_argument("--selector", default="balanced_accuracy", choices=["balanced_accuracy", "group_all_correct_rate"])
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    parser.add_argument("--predictions-output")
    args = parser.parse_args()

    payload, seed42_predictions = build_multisplit_report(
        read_jsonl(args.predictions),
        read_jsonl(args.hunk_candidates),
        seeds=parse_ints(args.seeds),
        calibration_fraction=args.calibration_fraction,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        l2=args.l2,
        thresholds=parse_floats(args.thresholds),
        selector=args.selector,
    )
    write_json(args.json_output, payload)
    if args.predictions_output:
        write_jsonl(args.predictions_output, seed42_predictions)
    if args.md_output:
        output = Path(args.md_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()

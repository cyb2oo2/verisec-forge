from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.evaluate_primevul_bucket_router import compute_binary_metrics, compute_group_metrics
from scripts.evaluate_primevul_pair_coupled_router import group_rows
from vrf.io_utils import read_jsonl, write_json, write_jsonl


FEATURE_NAMES = [
    "bias",
    "gap",
    "gap_squared",
    "top_probability",
    "second_probability",
    "mean_probability",
    "probability_distance_from_half",
    "changed_lines_max_log",
    "changed_lines_min_log",
    "same_bucket",
    "top_bucket_00_02",
    "top_bucket_03_05",
    "top_bucket_06_10",
    "top_bucket_11_25",
    "top_bucket_26plus",
]


def split_pair_keys(rows: list[dict[str, Any]], *, calibration_fraction: float, seed: int) -> dict[str, set[str]]:
    keys = sorted({str(row.get("pair_key") or row["id"]) for row in rows})
    rng = random.Random(seed)
    rng.shuffle(keys)
    calibration_count = int(round(len(keys) * calibration_fraction))
    calibration = set(keys[:calibration_count])
    return {"calibration": calibration, "eval": set(keys[calibration_count:])}


def filter_by_pair_keys(rows: list[dict[str, Any]], keys: set[str]) -> list[dict[str, Any]]:
    return [row for row in rows if str(row.get("pair_key") or row["id"]) in keys]


def bucket_feature_name(bucket: str) -> str:
    normalized = bucket.replace("+", "plus").replace("-", "_")
    return f"top_bucket_{normalized}"


def group_features(group: list[dict[str, Any]]) -> dict[str, float]:
    ordered = sorted(group, key=lambda row: float(row["vuln_probability"]), reverse=True)
    top = ordered[0]
    second = ordered[1] if len(ordered) > 1 else ordered[0]
    top_probability = float(top["vuln_probability"])
    second_probability = float(second["vuln_probability"])
    gap = top_probability - second_probability
    top_bucket = str(top.get("changed_line_bucket") or "unknown")
    values = {
        "bias": 1.0,
        "gap": gap,
        "gap_squared": gap * gap,
        "top_probability": top_probability,
        "second_probability": second_probability,
        "mean_probability": sum(float(row["vuln_probability"]) for row in ordered) / len(ordered),
        "probability_distance_from_half": abs(top_probability - 0.5),
        "changed_lines_max_log": math.log1p(max(float(row.get("changed_lines") or 0.0) for row in ordered)),
        "changed_lines_min_log": math.log1p(min(float(row.get("changed_lines") or 0.0) for row in ordered)),
        "same_bucket": float(len({str(row.get("changed_line_bucket")) for row in ordered}) == 1),
        "top_bucket_00_02": 0.0,
        "top_bucket_03_05": 0.0,
        "top_bucket_06_10": 0.0,
        "top_bucket_11_25": 0.0,
        "top_bucket_26plus": 0.0,
    }
    feature_name = bucket_feature_name(top_bucket)
    if feature_name in values:
        values[feature_name] = 1.0
    return values


def orientation_wrong(group: list[dict[str, Any]]) -> int:
    ordered = sorted(group, key=lambda row: float(row["vuln_probability"]), reverse=True)
    return int(int(ordered[0]["gold"]) != 1)


def sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def dot(weights: dict[str, float], features: dict[str, float]) -> float:
    return sum(weights.get(name, 0.0) * features.get(name, 0.0) for name in FEATURE_NAMES)


def train_gate(
    groups: list[list[dict[str, Any]]],
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
            values = group_features(group)
            prediction = sigmoid(dot(weights, values))
            error = prediction - label
            for name in FEATURE_NAMES:
                weights[name] -= learning_rate * (error * values.get(name, 0.0) + l2 * weights[name])
    return weights


def score_groups(groups: list[list[dict[str, Any]]], weights: dict[str, float]) -> list[dict[str, Any]]:
    scored = []
    for group in groups:
        values = group_features(group)
        scored.append(
            {
                "pair_key": str(group[0].get("pair_key") or group[0]["id"]),
                "orientation_wrong": orientation_wrong(group),
                "inversion_probability": sigmoid(dot(weights, values)),
                "features": values,
            }
        )
    return scored


def apply_gate(rows: list[dict[str, Any]], group_scores: dict[str, dict[str, Any]], *, threshold: float) -> tuple[list[dict[str, Any]], dict[str, int]]:
    corrected = []
    counts = {"rows": len(rows), "groups": len(group_scores), "gated_groups": 0, "gated_rows": 0}
    gated_groups = {
        pair_key
        for pair_key, score in group_scores.items()
        if float(score["inversion_probability"]) >= threshold
    }
    counts["gated_groups"] = len(gated_groups)
    for row in rows:
        pair_key = str(row.get("pair_key") or row["id"])
        updated = dict(row)
        updated["side_correction_score"] = float(group_scores[pair_key]["inversion_probability"])
        updated["side_correction_threshold"] = threshold
        updated["side_correction_applied"] = pair_key in gated_groups
        if pair_key in gated_groups:
            updated["pred"] = int(updated.get("pre_coupled_pred", updated["pred"]))
            counts["gated_rows"] += 1
        corrected.append(updated)
    return corrected, counts


def report_for_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "overall": compute_binary_metrics(rows),
        "group_metrics": compute_group_metrics(rows),
    }


def select_threshold(
    rows: list[dict[str, Any]],
    group_scores: list[dict[str, Any]],
    *,
    thresholds: list[float],
    selector: str,
) -> dict[str, Any]:
    by_pair = {row["pair_key"]: row for row in group_scores}
    sweep = []
    for threshold in thresholds:
        corrected, counts = apply_gate(rows, by_pair, threshold=threshold)
        metrics = report_for_rows(corrected)
        sweep.append({"threshold": threshold, "gate_counts": counts, **metrics})
    if selector == "balanced_accuracy":
        selected = max(sweep, key=lambda row: (row["overall"]["balanced_accuracy"], row["group_metrics"]["group_all_correct_rate"], -row["threshold"]))
    elif selector == "group_all_correct_rate":
        selected = max(sweep, key=lambda row: (row["group_metrics"]["group_all_correct_rate"], row["overall"]["balanced_accuracy"], -row["threshold"]))
    else:
        raise ValueError(f"Unsupported selector: {selector}")
    selected["selection_scores"] = {
        "primary_metric": selector,
        "primary_score": selected["overall"]["balanced_accuracy"] if selector == "balanced_accuracy" else selected["group_metrics"]["group_all_correct_rate"],
        "tie_break": "lowest_threshold",
        "tie_break_value": selected["threshold"],
    }
    return {"selected": selected, "sweep": sweep}


def parse_floats(value: str) -> list[float]:
    parsed = [float(part.strip()) for part in value.split(",") if part.strip()]
    if not parsed:
        raise ValueError("At least one threshold is required")
    return parsed


def build_report(
    rows: list[dict[str, Any]],
    *,
    calibration_fraction: float,
    seed: int,
    epochs: int,
    learning_rate: float,
    l2: float,
    thresholds: list[float],
    selector: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    split = split_pair_keys(rows, calibration_fraction=calibration_fraction, seed=seed)
    calibration_rows = filter_by_pair_keys(rows, split["calibration"])
    eval_rows = filter_by_pair_keys(rows, split["eval"])
    calibration_groups = list(group_rows(calibration_rows).values())
    eval_groups = list(group_rows(eval_rows).values())
    weights = train_gate(calibration_groups, epochs=epochs, learning_rate=learning_rate, l2=l2, seed=seed)
    calibration_scores = score_groups(calibration_groups, weights)
    eval_scores = score_groups(eval_groups, weights)
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


def render_markdown(report: dict[str, Any]) -> str:
    baseline = report["eval"]["baseline_pair_coupled"]
    corrected = report["eval"]["corrected"]
    lines = [
        "# PrimeVul Pair-Side Correction Gate",
        "",
        "This report trains a lightweight gate on calibration pair groups to detect likely side inversions. If a held-out pair group is gated, the system falls back from pair-coupled labels to the pre-coupled predictions. It is a correction-layer diagnostic, not a new model checkpoint.",
        "",
        "## Protocol",
        "",
        f"- Calibration pair groups: `{report['split']['calibration_pair_count']}`",
        f"- Held-out eval pair groups: `{report['split']['eval_pair_count']}`",
        f"- Selector: `{report['config']['selector']}`",
        f"- Selected gate threshold: `{report['calibration']['selection']['threshold']}`",
        f"- Held-out gated groups: `{corrected['gate_counts']['gated_groups']}`",
        "",
        "## Held-Out Eval",
        "",
        "| system | bal_acc | recall | specificity | f1 | group_all_correct | orientation | fp | fn |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, metrics in [("pair_coupled", baseline), ("correction_gate", corrected)]:
        lines.append(
            "| "
            + " | ".join(
                [
                    name,
                    str(metrics["overall"]["balanced_accuracy"]),
                    str(metrics["overall"]["vulnerable_recall"]),
                    str(metrics["overall"]["safe_specificity"]),
                    str(metrics["overall"]["f1"]),
                    str(metrics["group_metrics"]["group_all_correct_rate"]),
                    str(metrics["group_metrics"]["orientation_accuracy"]),
                    str(metrics["overall"]["fp"]),
                    str(metrics["overall"]["fn"]),
                ]
            )
            + " |"
        )
    lines.extend(["", "## Calibration Sweep", "", "| threshold | bal_acc | group_all_correct | gated_groups |", "| ---: | ---: | ---: | ---: |"])
    for row in report["calibration"]["sweep"]:
        lines.append(
            f"| {row['threshold']} | {row['overall']['balanced_accuracy']} | {row['group_metrics']['group_all_correct_rate']} | {row['gate_counts']['gated_groups']} |"
        )
    lines.extend(["", "## Learned Weights", ""])
    for name, value in report["weights_ranked"]:
        lines.append(f"- `{name}`: `{value}`")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A positive held-out gain would support a separate pair-side correction layer. A flat or negative result means the confident inversion set is still valuable for diagnosis, but its signal is not yet captured by these cheap metadata/probability features.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a lightweight PrimeVul pair-side correction gate.")
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--calibration-fraction", type=float, default=0.3)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=80)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--l2", type=float, default=0.0001)
    parser.add_argument("--thresholds", default="0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9")
    parser.add_argument("--selector", default="balanced_accuracy", choices=["balanced_accuracy", "group_all_correct_rate"])
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    parser.add_argument("--predictions-output")
    args = parser.parse_args()

    report, corrected_rows = build_report(
        read_jsonl(args.predictions),
        calibration_fraction=args.calibration_fraction,
        seed=args.seed,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        l2=args.l2,
        thresholds=parse_floats(args.thresholds),
        selector=args.selector,
    )
    write_json(args.json_output, report)
    if args.predictions_output:
        write_jsonl(args.predictions_output, corrected_rows)
    if args.md_output:
        output = Path(args.md_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({"eval": report["eval"], "selection": report["calibration"]["selection"]["threshold"]}, indent=2))


if __name__ == "__main__":
    main()

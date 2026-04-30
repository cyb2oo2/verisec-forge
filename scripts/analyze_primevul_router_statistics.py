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

from scripts.evaluate_primevul_bucket_router import load_prediction_queues, route_predictions
from scripts.evaluate_primevul_bucket_router_calibrated import filter_by_pair_keys, split_pair_keys
from vrf.io_utils import read_json, read_jsonl, write_json


def group_rows(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("pair_key") or row["id"])].append(row)
    return grouped


def group_all_correct(group: list[dict[str, Any]]) -> int:
    return int(all(row["gold"] == row["pred"] for row in group))


def orientation_value(group: list[dict[str, Any]]) -> int | None:
    positives = [row for row in group if row["gold"] == 1]
    negatives = [row for row in group if row["gold"] == 0]
    if not positives or not negatives:
        return None
    pos_prob = sum(float(row["vuln_probability"]) for row in positives) / len(positives)
    neg_prob = sum(float(row["vuln_probability"]) for row in negatives) / len(negatives)
    return int(pos_prob > neg_prob)


def group_metric_values(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    values: dict[str, dict[str, int]] = {}
    for pair_key, group in group_rows(rows).items():
        orientation = orientation_value(group)
        values[pair_key] = {
            "group_all_correct": group_all_correct(group),
            "orientation": orientation if orientation is not None else -1,
            "orientation_eligible": int(orientation is not None),
        }
    return values


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = (len(ordered) - 1) * q
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    weight = index - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def bootstrap_metric(
    values: dict[str, dict[str, int]],
    *,
    metric: str,
    iterations: int,
    seed: int,
) -> dict[str, Any]:
    rng = random.Random(seed)
    pair_keys = sorted(values)
    samples: list[float] = []
    for _ in range(iterations):
        selected = [rng.choice(pair_keys) for _ in pair_keys]
        if metric == "orientation":
            eligible = [values[key][metric] for key in selected if values[key]["orientation_eligible"]]
        else:
            eligible = [values[key][metric] for key in selected]
        samples.append(mean([float(value) for value in eligible]))
    observed_values = (
        [values[key][metric] for key in pair_keys if values[key]["orientation_eligible"]]
        if metric == "orientation"
        else [values[key][metric] for key in pair_keys]
    )
    return {
        "observed": round(mean([float(value) for value in observed_values]), 4),
        "ci95_low": round(percentile(samples, 0.025), 4),
        "ci95_high": round(percentile(samples, 0.975), 4),
        "iterations": iterations,
        "seed": seed,
        "units": len(observed_values),
    }


def bootstrap_delta(
    baseline: dict[str, dict[str, int]],
    router: dict[str, dict[str, int]],
    *,
    metric: str,
    iterations: int,
    seed: int,
) -> dict[str, Any]:
    rng = random.Random(seed)
    pair_keys = sorted(set(baseline) & set(router))
    samples: list[float] = []
    for _ in range(iterations):
        selected = [rng.choice(pair_keys) for _ in pair_keys]
        if metric == "orientation":
            deltas = [
                router[key][metric] - baseline[key][metric]
                for key in selected
                if router[key]["orientation_eligible"] and baseline[key]["orientation_eligible"]
            ]
        else:
            deltas = [router[key][metric] - baseline[key][metric] for key in selected]
        samples.append(mean([float(value) for value in deltas]))
    observed_deltas = (
        [
            router[key][metric] - baseline[key][metric]
            for key in pair_keys
            if router[key]["orientation_eligible"] and baseline[key]["orientation_eligible"]
        ]
        if metric == "orientation"
        else [router[key][metric] - baseline[key][metric] for key in pair_keys]
    )
    return {
        "observed_delta": round(mean([float(value) for value in observed_deltas]), 4),
        "ci95_low": round(percentile(samples, 0.025), 4),
        "ci95_high": round(percentile(samples, 0.975), 4),
        "iterations": iterations,
        "seed": seed,
        "units": len(observed_deltas),
    }


def exact_sign_test(
    baseline: dict[str, dict[str, int]],
    router: dict[str, dict[str, int]],
    *,
    metric: str,
) -> dict[str, Any]:
    wins = 0
    losses = 0
    ties = 0
    for key in sorted(set(baseline) & set(router)):
        if metric == "orientation" and not (baseline[key]["orientation_eligible"] and router[key]["orientation_eligible"]):
            continue
        delta = router[key][metric] - baseline[key][metric]
        if delta > 0:
            wins += 1
        elif delta < 0:
            losses += 1
        else:
            ties += 1
    n = wins + losses
    if n == 0:
        p_value = 1.0
    else:
        smaller = min(wins, losses)
        p_value = min(1.0, 2 * sum(math.comb(n, k) for k in range(smaller + 1)) / (2**n))
    return {
        "wins": wins,
        "losses": losses,
        "ties": ties,
        "two_sided_p_value": round(p_value, 6),
        "test": "exact_sign_test",
    }


def route_eval_rows(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    dataset_rows = read_jsonl(report["dataset"])
    split = split_pair_keys(
        dataset_rows,
        calibration_fraction=float(report["split"]["calibration_fraction"]),
        seed=int(report["split"]["seed"]),
    )
    eval_rows = filter_by_pair_keys(dataset_rows, split["eval"])
    default_predictions = report["default_predictions"]
    bucket_predictions = report["bucket_predictions"]
    bucket = report["bucket"]
    default_threshold = float(report["selection"]["thresholds"]["default"])
    bucket_threshold = float(report["selection"]["thresholds"]["bucket"])
    baseline_rows, _ = route_predictions(
        eval_rows,
        load_prediction_queues(default_predictions),
        load_prediction_queues(default_predictions),
        bucket=bucket,
        default_threshold=default_threshold,
        bucket_threshold=default_threshold,
    )
    router_rows, _ = route_predictions(
        eval_rows,
        load_prediction_queues(default_predictions),
        load_prediction_queues(bucket_predictions),
        bucket=bucket,
        default_threshold=default_threshold,
        bucket_threshold=bucket_threshold,
    )
    return baseline_rows, router_rows


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Router Statistical Analysis",
        "",
        "This report estimates uncertainty for the validation-selected bucket router on held-out pair groups.",
        "",
        "## Bootstrap 95% Confidence Intervals",
        "",
        "| system | metric | observed | ci95_low | ci95_high | units |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for system_name in ["baseline", "router"]:
        for metric_name, row in payload["bootstrap"][system_name].items():
            lines.append(
                f"| {system_name} | {metric_name} | {row['observed']} | {row['ci95_low']} | {row['ci95_high']} | {row['units']} |"
            )
    lines.extend(
        [
            "",
            "## Router Minus Baseline",
            "",
            "| metric | delta | ci95_low | ci95_high | sign wins | sign losses | sign p |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for metric_name, row in payload["delta"].items():
        sign = payload["sign_tests"][metric_name]
        lines.append(
            f"| {metric_name} | {row['observed_delta']} | {row['ci95_low']} | {row['ci95_high']} | {sign['wins']} | {sign['losses']} | {sign['two_sided_p_value']} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "The router's observed gains are small. They should be treated as pair-consistency evidence, not as a statistically decisive detector improvement unless the confidence intervals and sign tests support that claim on larger or external splits.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap and paired-test the PrimeVul calibrated bucket router.")
    parser.add_argument("--report", default="reports/secure_code_primevul_directional_bucket_router_calibrated_v1_report.json")
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    args = parser.parse_args()

    report = read_json(args.report)
    baseline_rows, router_rows = route_eval_rows(report)
    baseline_values = group_metric_values(baseline_rows)
    router_values = group_metric_values(router_rows)
    metrics = ["group_all_correct", "orientation"]
    payload = {
        "source_report": args.report,
        "iterations": args.iterations,
        "seed": args.seed,
        "bootstrap": {
            "baseline": {
                metric: bootstrap_metric(baseline_values, metric=metric, iterations=args.iterations, seed=args.seed)
                for metric in metrics
            },
            "router": {
                metric: bootstrap_metric(router_values, metric=metric, iterations=args.iterations, seed=args.seed)
                for metric in metrics
            },
        },
        "delta": {
            metric: bootstrap_delta(
                baseline_values,
                router_values,
                metric=metric,
                iterations=args.iterations,
                seed=args.seed,
            )
            for metric in metrics
        },
        "sign_tests": {
            metric: exact_sign_test(baseline_values, router_values, metric=metric)
            for metric in metrics
        },
    }
    write_json(args.json_output, payload)
    if args.md_output:
        output = Path(args.md_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["delta"], indent=2))


if __name__ == "__main__":
    main()

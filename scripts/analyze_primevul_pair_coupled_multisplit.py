from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.analyze_primevul_router_statistics import exact_sign_test, group_metric_values
from scripts.evaluate_primevul_bucket_router_calibrated import (
    build_report_for_threshold,
    filter_by_pair_keys,
    parse_thresholds,
    select_threshold,
    split_pair_keys,
)
from scripts.evaluate_primevul_pair_coupled_router import apply_pair_coupling, parse_margins, report_for_rows, select_margin
from vrf.io_utils import read_json, read_jsonl, write_json


def mcnemar_exact(rows_a: list[dict[str, Any]], rows_b: list[dict[str, Any]]) -> dict[str, Any]:
    by_id_a = {f"{row['id']}::{index}": row for index, row in enumerate(rows_a)}
    by_id_b = {f"{row['id']}::{index}": row for index, row in enumerate(rows_b)}
    if set(by_id_a) != set(by_id_b):
        raise ValueError("McNemar inputs must contain the same ordered rows")
    a_correct_b_wrong = 0
    a_wrong_b_correct = 0
    both_correct = 0
    both_wrong = 0
    for key in by_id_a:
        a_correct = by_id_a[key]["gold"] == by_id_a[key]["pred"]
        b_correct = by_id_b[key]["gold"] == by_id_b[key]["pred"]
        if a_correct and b_correct:
            both_correct += 1
        elif not a_correct and not b_correct:
            both_wrong += 1
        elif a_correct and not b_correct:
            a_correct_b_wrong += 1
        else:
            a_wrong_b_correct += 1
    discordant = a_correct_b_wrong + a_wrong_b_correct
    if discordant == 0:
        p_value = 1.0
    else:
        smaller = min(a_correct_b_wrong, a_wrong_b_correct)
        p_value = min(1.0, 2 * sum(math.comb(discordant, k) for k in range(smaller + 1)) / (2**discordant))
    rounded = round(p_value, 6)
    if p_value > 0 and rounded == 0:
        rounded = 0.000001
    return {
        "a_correct_b_wrong": a_correct_b_wrong,
        "a_wrong_b_correct": a_wrong_b_correct,
        "both_correct": both_correct,
        "both_wrong": both_wrong,
        "discordant": discordant,
        "two_sided_p_value": rounded,
        "test": "exact_mcnemar",
    }


def delta(metric_a: float, metric_b: float) -> float:
    return round(metric_b - metric_a, 4)


def evaluate_seed(
    *,
    seed: int,
    dataset_rows: list[dict[str, Any]],
    default_predictions: str,
    bucket_predictions: str,
    bucket: str,
    calibration_fraction: float,
    default_threshold: float,
    bucket_thresholds: list[float],
    margins: list[float],
    bucket_selector: str,
    margin_selector: str,
) -> dict[str, Any]:
    split = split_pair_keys(dataset_rows, calibration_fraction=calibration_fraction, seed=seed)
    calibration_rows = filter_by_pair_keys(dataset_rows, split["calibration"])
    eval_rows = filter_by_pair_keys(dataset_rows, split["eval"])

    bucket_sweep: list[dict[str, Any]] = []
    for threshold in bucket_thresholds:
        _, metrics = build_report_for_threshold(
            calibration_rows,
            default_predictions_path=default_predictions,
            bucket_predictions_path=bucket_predictions,
            bucket=bucket,
            default_threshold=default_threshold,
            bucket_threshold=threshold,
        )
        bucket_sweep.append({"bucket_threshold": threshold, **metrics})
    selected_bucket = select_threshold(bucket_sweep, selector=bucket_selector)
    bucket_threshold = float(selected_bucket["bucket_threshold"])

    route_kwargs = {
        "default_predictions_path": default_predictions,
        "bucket_predictions_path": bucket_predictions,
        "bucket": bucket,
        "default_threshold": default_threshold,
        "bucket_threshold": bucket_threshold,
    }
    calibration_router_rows, calibration_router_metrics = build_report_for_threshold(calibration_rows, **route_kwargs)
    margin_sweep: list[dict[str, Any]] = []
    for margin in margins:
        coupled_rows, coupling_counts = apply_pair_coupling(calibration_router_rows, margin=margin)
        margin_sweep.append(
            {
                "margin": margin,
                **report_for_rows(
                    coupled_rows,
                    thresholds=calibration_router_metrics["thresholds"],
                    route_counts=calibration_router_metrics["route_counts"],
                    coupling_counts=coupling_counts,
                ),
            }
        )
    selected_margin = select_margin(margin_sweep, selector=margin_selector)
    margin = float(selected_margin["margin"])

    baseline_rows, baseline_metrics = build_report_for_threshold(
        eval_rows,
        default_predictions_path=default_predictions,
        bucket_predictions_path=default_predictions,
        bucket=bucket,
        default_threshold=default_threshold,
        bucket_threshold=default_threshold,
    )
    bucket_rows, bucket_metrics = build_report_for_threshold(eval_rows, **route_kwargs)
    pair_rows, coupling_counts = apply_pair_coupling(bucket_rows, margin=margin)
    pair_metrics = report_for_rows(
        pair_rows,
        thresholds=bucket_metrics["thresholds"],
        route_counts=bucket_metrics["route_counts"],
        coupling_counts=coupling_counts,
    )
    bucket_group_values = group_metric_values(bucket_rows)
    pair_group_values = group_metric_values(pair_rows)
    return {
        "seed": seed,
        "split": {
            "calibration_pair_count": len(split["calibration"]),
            "eval_pair_count": len(split["eval"]),
            "calibration_rows": len(calibration_rows),
            "eval_rows": len(eval_rows),
        },
        "selection": {
            "bucket_threshold": bucket_threshold,
            "bucket_selector": bucket_selector,
            "margin": margin,
            "margin_selector": margin_selector,
            "bucket_calibration_score": selected_bucket["overall"][bucket_selector],
            "margin_calibration_score": selected_margin["group_metrics"].get(margin_selector)
            if margin_selector in selected_margin["group_metrics"]
            else selected_margin["overall"][margin_selector],
        },
        "baseline": baseline_metrics,
        "bucket_router": bucket_metrics,
        "pair_coupled": pair_metrics,
        "deltas": {
            "bucket_minus_baseline_balanced_accuracy": delta(
                baseline_metrics["overall"]["balanced_accuracy"],
                bucket_metrics["overall"]["balanced_accuracy"],
            ),
            "pair_minus_bucket_balanced_accuracy": delta(
                bucket_metrics["overall"]["balanced_accuracy"],
                pair_metrics["overall"]["balanced_accuracy"],
            ),
            "pair_minus_bucket_group_all_correct": delta(
                bucket_metrics["group_metrics"]["group_all_correct_rate"],
                pair_metrics["group_metrics"]["group_all_correct_rate"],
            ),
            "pair_minus_bucket_orientation": delta(
                bucket_metrics["group_metrics"]["orientation_accuracy"],
                pair_metrics["group_metrics"]["orientation_accuracy"],
            ),
        },
        "tests": {
            "pair_vs_bucket_row_mcnemar": mcnemar_exact(bucket_rows, pair_rows),
            "pair_vs_bucket_group_all_correct_sign": exact_sign_test(
                bucket_group_values,
                pair_group_values,
                metric="group_all_correct",
            ),
            "pair_vs_bucket_orientation_sign": exact_sign_test(
                bucket_group_values,
                pair_group_values,
                metric="orientation",
            ),
        },
    }


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "mean": round(statistics.mean(values), 4),
        "stdev": round(statistics.stdev(values), 4) if len(values) > 1 else 0.0,
        "min": round(min(values), 4),
        "max": round(max(values), 4),
    }


def build_summary(seed_reports: list[dict[str, Any]]) -> dict[str, Any]:
    fields = {
        "baseline_balanced_accuracy": [row["baseline"]["overall"]["balanced_accuracy"] for row in seed_reports],
        "bucket_balanced_accuracy": [row["bucket_router"]["overall"]["balanced_accuracy"] for row in seed_reports],
        "pair_balanced_accuracy": [row["pair_coupled"]["overall"]["balanced_accuracy"] for row in seed_reports],
        "bucket_group_all_correct": [row["bucket_router"]["group_metrics"]["group_all_correct_rate"] for row in seed_reports],
        "pair_group_all_correct": [row["pair_coupled"]["group_metrics"]["group_all_correct_rate"] for row in seed_reports],
        "pair_minus_bucket_balanced_accuracy": [row["deltas"]["pair_minus_bucket_balanced_accuracy"] for row in seed_reports],
        "pair_minus_bucket_group_all_correct": [row["deltas"]["pair_minus_bucket_group_all_correct"] for row in seed_reports],
    }
    return {field: summarize(values) for field, values in fields.items()}


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Pair-Coupled Multi-Split Analysis",
        "",
        "This report repeats calibration/evaluation over multiple pair-key split seeds. Each seed independently selects the bucket threshold and pair-coupling margin on its calibration pair groups, then reports on held-out pair groups.",
        "",
        "## Summary",
        "",
        "| metric | mean | stdev | min | max |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for metric, row in payload["summary"].items():
        lines.append(f"| {metric} | {row['mean']} | {row['stdev']} | {row['min']} | {row['max']} |")
    lines.extend(
        [
            "",
            "## Per-Seed Results",
            "",
            "| seed | bucket_th | margin | baseline_bal | bucket_bal | pair_bal | bucket_group | pair_group | pair-bucket bal | pair-bucket group | McNemar p | group sign p |",
            "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in payload["seeds"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    str(row["seed"]),
                    str(row["selection"]["bucket_threshold"]),
                    str(row["selection"]["margin"]),
                    str(row["baseline"]["overall"]["balanced_accuracy"]),
                    str(row["bucket_router"]["overall"]["balanced_accuracy"]),
                    str(row["pair_coupled"]["overall"]["balanced_accuracy"]),
                    str(row["bucket_router"]["group_metrics"]["group_all_correct_rate"]),
                    str(row["pair_coupled"]["group_metrics"]["group_all_correct_rate"]),
                    str(row["deltas"]["pair_minus_bucket_balanced_accuracy"]),
                    str(row["deltas"]["pair_minus_bucket_group_all_correct"]),
                    str(row["tests"]["pair_vs_bucket_row_mcnemar"]["two_sided_p_value"]),
                    str(row["tests"]["pair_vs_bucket_group_all_correct_sign"]["two_sided_p_value"]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "This is the reviewer-facing stability check. Pair-coupled decoding should be described as credible only if the pair-coupled deltas remain positive across split seeds and paired tests are consistently favorable.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run multi-split stability analysis for PrimeVul pair-coupled decoding.")
    parser.add_argument("--calibrated-report", default="reports/secure_code_primevul_directional_bucket_router_calibrated_v1_report.json")
    parser.add_argument("--seeds", default="7,13,42,99,123")
    parser.add_argument("--bucket-thresholds", default="0.5,0.6,0.7,0.8,0.9")
    parser.add_argument("--margins", default="0.0,0.02,0.05,0.1,0.2")
    parser.add_argument("--bucket-selector", default="balanced_accuracy", choices=["balanced_accuracy", "f1"])
    parser.add_argument("--margin-selector", default="group_all_correct_rate", choices=["balanced_accuracy", "f1", "orientation_accuracy", "group_all_correct_rate"])
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    args = parser.parse_args()

    calibrated = read_json(args.calibrated_report)
    dataset_rows = read_jsonl(calibrated["dataset"])
    seed_values = [int(part.strip()) for part in args.seeds.split(",") if part.strip()]
    reports = [
        evaluate_seed(
            seed=seed,
            dataset_rows=dataset_rows,
            default_predictions=calibrated["default_predictions"],
            bucket_predictions=calibrated["bucket_predictions"],
            bucket=calibrated["bucket"],
            calibration_fraction=float(calibrated["split"]["calibration_fraction"]),
            default_threshold=float(calibrated["selection"]["thresholds"]["default"]),
            bucket_thresholds=parse_thresholds(args.bucket_thresholds),
            margins=parse_margins(args.margins),
            bucket_selector=args.bucket_selector,
            margin_selector=args.margin_selector,
        )
        for seed in seed_values
    ]
    payload = {
        "source_report": args.calibrated_report,
        "seeds_requested": seed_values,
        "bucket_thresholds": parse_thresholds(args.bucket_thresholds),
        "margins": parse_margins(args.margins),
        "summary": build_summary(reports),
        "seeds": reports,
    }
    write_json(args.json_output, payload)
    if args.md_output:
        output = Path(args.md_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()

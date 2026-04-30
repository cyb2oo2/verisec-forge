from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.evaluate_primevul_bucket_router import compute_binary_metrics, compute_group_metrics, render_markdown, summarize_by_bucket
from scripts.evaluate_primevul_bucket_router_calibrated import (
    build_report_for_threshold,
    exact_binary_metric,
    filter_by_pair_keys,
    split_pair_keys,
)
from vrf.io_utils import read_json, read_jsonl, write_json, write_jsonl


def parse_margins(value: str) -> list[float]:
    margins = [float(part.strip()) for part in value.split(",") if part.strip()]
    if not margins:
        raise ValueError("At least one coupling margin is required")
    return margins


def group_rows(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("pair_key") or row["id"])].append(row)
    return grouped


def apply_pair_coupling(rows: list[dict[str, Any]], *, margin: float) -> tuple[list[dict[str, Any]], dict[str, int]]:
    coupled = [dict(row) for row in rows]
    by_pair = group_rows(coupled)
    counts = {
        "groups": len(by_pair),
        "eligible_groups": 0,
        "coupled_groups": 0,
        "unchanged_groups": 0,
    }
    for group in by_pair.values():
        if len(group) < 2:
            counts["unchanged_groups"] += 1
            continue
        counts["eligible_groups"] += 1
        sorted_group = sorted(group, key=lambda row: float(row["vuln_probability"]), reverse=True)
        top = sorted_group[0]
        second = sorted_group[1]
        gap = float(top["vuln_probability"]) - float(second["vuln_probability"])
        if gap < margin:
            counts["unchanged_groups"] += 1
            continue
        for index, row in enumerate(sorted_group):
            row["pre_coupled_pred"] = row["pred"]
            row["pair_coupled"] = True
            row["pair_probability_gap"] = gap
            row["pred"] = 1 if index == 0 else 0
        counts["coupled_groups"] += 1
    for row in coupled:
        row.setdefault("pre_coupled_pred", row["pred"])
        row.setdefault("pair_coupled", False)
        row.setdefault("pair_probability_gap", 0.0)
    return coupled, counts


def report_for_rows(rows: list[dict[str, Any]], *, thresholds: dict[str, float], route_counts: dict[str, int], coupling_counts: dict[str, int]) -> dict[str, Any]:
    return {
        "thresholds": thresholds,
        "route_counts": route_counts,
        "coupling_counts": coupling_counts,
        "overall": compute_binary_metrics(rows),
        "group_metrics": compute_group_metrics(rows),
        "by_bucket": summarize_by_bucket(rows),
    }


def exact_group_metric(metrics: dict[str, Any], selector: str) -> float:
    if selector == "group_all_correct_rate":
        if not {"unique_pair_count", "group_all_correct"}.issubset(metrics):
            return float(metrics[selector])
        denominator = int(metrics["unique_pair_count"])
        return int(metrics["group_all_correct"]) / denominator if denominator else 0.0
    if selector == "orientation_accuracy":
        if not {"orientation_eligible_pair_count", "orientation_correct"}.issubset(metrics):
            return float(metrics[selector])
        denominator = int(metrics["orientation_eligible_pair_count"])
        return int(metrics["orientation_correct"]) / denominator if denominator else 0.0
    raise ValueError(f"Unsupported group metric selector: {selector}")


def select_margin(rows: list[dict[str, Any]], *, selector: str) -> dict[str, Any]:
    if selector not in {"balanced_accuracy", "f1", "orientation_accuracy", "group_all_correct_rate"}:
        raise ValueError(f"Unsupported selector: {selector}")
    if selector in {"orientation_accuracy", "group_all_correct_rate"}:
        selected = max(
            rows,
            key=lambda row: (
                exact_group_metric(row["group_metrics"], selector),
                exact_binary_metric(row["overall"], "balanced_accuracy"),
                -row["margin"],
            ),
        )
        selected["selection_scores"] = {
            "primary_metric": selector,
            "primary_score": exact_group_metric(selected["group_metrics"], selector),
            "secondary_metric": "balanced_accuracy",
            "secondary_score": exact_binary_metric(selected["overall"], "balanced_accuracy"),
            "tie_break": "lowest_margin",
            "tie_break_value": float(selected["margin"]),
        }
        return selected
    selected = max(
        rows,
        key=lambda row: (
            exact_binary_metric(row["overall"], selector),
            exact_group_metric(row["group_metrics"], "orientation_accuracy"),
            -row["margin"],
        ),
    )
    selected["selection_scores"] = {
        "primary_metric": selector,
        "primary_score": exact_binary_metric(selected["overall"], selector),
        "secondary_metric": "orientation_accuracy",
        "secondary_score": exact_group_metric(selected["group_metrics"], "orientation_accuracy"),
        "tie_break": "lowest_margin",
        "tie_break_value": float(selected["margin"]),
    }
    return selected


def render_pair_coupled_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Pair-Coupled Router",
        "",
        "This report applies pair-level decoding on top of the validation-selected bucket router. Eligible pair groups are forced to assign the higher-probability side as vulnerable and the lower-probability side as safe when the probability gap exceeds the selected margin.",
        "",
        "## Protocol",
        "",
        f"- Calibration pair groups: `{report['split']['calibration_pair_count']}`",
        f"- Held-out eval pair groups: `{report['split']['eval_pair_count']}`",
        f"- Selector: `{report['selection']['selector']}`",
        f"- Selected margin: `{report['selection']['margin']}`",
        f"- Tie-break policy: `{report['selection']['selection_scores']['tie_break']}`",
        f"- Selection score (unrounded): `{report['selection']['selection_scores']['primary_metric']}={report['selection']['selection_scores']['primary_score']}`",
        "",
        "## Calibration Sweep",
        "",
        "| margin | bal_acc | recall | specificity | f1 | group_all_correct | orientation | coupled_groups |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in report["calibration_sweep"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    str(row["margin"]),
                    str(row["overall"]["balanced_accuracy"]),
                    str(row["overall"]["vulnerable_recall"]),
                    str(row["overall"]["safe_specificity"]),
                    str(row["overall"]["f1"]),
                    str(row["group_metrics"]["group_all_correct_rate"]),
                    str(row["group_metrics"]["orientation_accuracy"]),
                    str(row["coupling_counts"]["coupled_groups"]),
                ]
            )
            + " |"
        )
    lines.extend(["", "## Held-Out Eval", ""])
    eval_report = {
        "thresholds": report["eval"]["thresholds"],
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
            "| system | bal_acc | recall | specificity | f1 | group_all_correct | orientation |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for name in ["baseline_direction_aware", "bucket_router"]:
        control = report["same_split_controls"][name]
        lines.append(
            "| "
            + " | ".join(
                [
                    name,
                    str(control["overall"]["balanced_accuracy"]),
                    str(control["overall"]["vulnerable_recall"]),
                    str(control["overall"]["safe_specificity"]),
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
    parser = argparse.ArgumentParser(description="Evaluate pair-coupled decoding on top of the calibrated PrimeVul bucket router.")
    parser.add_argument("--calibrated-report", default="reports/secure_code_primevul_directional_bucket_router_calibrated_v1_report.json")
    parser.add_argument("--margins", default="0.0,0.02,0.05,0.1,0.2")
    parser.add_argument("--selector", default="orientation_accuracy", choices=["balanced_accuracy", "f1", "orientation_accuracy", "group_all_correct_rate"])
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    parser.add_argument("--predictions-output")
    args = parser.parse_args()

    calibrated = read_json(args.calibrated_report)
    dataset_rows = read_jsonl(calibrated["dataset"])
    split = split_pair_keys(
        dataset_rows,
        calibration_fraction=float(calibrated["split"]["calibration_fraction"]),
        seed=int(calibrated["split"]["seed"]),
    )
    calibration_rows = filter_by_pair_keys(dataset_rows, split["calibration"])
    eval_rows = filter_by_pair_keys(dataset_rows, split["eval"])
    thresholds = calibrated["selection"]["thresholds"]
    bucket = calibrated["bucket"]
    route_kwargs = {
        "default_predictions_path": calibrated["default_predictions"],
        "bucket_predictions_path": calibrated["bucket_predictions"],
        "bucket": bucket,
        "default_threshold": float(thresholds["default"]),
        "bucket_threshold": float(thresholds["bucket"]),
    }
    baseline_calibration_rows, base_calibration_metrics = build_report_for_threshold(calibration_rows, **route_kwargs)
    calibration_sweep: list[dict[str, Any]] = []
    for margin in parse_margins(args.margins):
        coupled_rows, coupling_counts = apply_pair_coupling(baseline_calibration_rows, margin=margin)
        calibration_sweep.append(
            {
                "margin": margin,
                **report_for_rows(
                    coupled_rows,
                    thresholds=base_calibration_metrics["thresholds"],
                    route_counts=base_calibration_metrics["route_counts"],
                    coupling_counts=coupling_counts,
                ),
            }
        )
    selected = select_margin(calibration_sweep, selector=args.selector)

    router_eval_rows, router_eval_metrics = build_report_for_threshold(eval_rows, **route_kwargs)
    coupled_eval_rows, coupling_counts = apply_pair_coupling(router_eval_rows, margin=float(selected["margin"]))
    eval_metrics = report_for_rows(
        coupled_eval_rows,
        thresholds=router_eval_metrics["thresholds"],
        route_counts=router_eval_metrics["route_counts"],
        coupling_counts=coupling_counts,
    )
    _, baseline_eval_metrics = build_report_for_threshold(
        eval_rows,
        default_predictions_path=calibrated["default_predictions"],
        bucket_predictions_path=calibrated["default_predictions"],
        bucket=bucket,
        default_threshold=float(thresholds["default"]),
        bucket_threshold=float(thresholds["default"]),
    )
    report = {
        "source_report": args.calibrated_report,
        "bucket": bucket,
        "split": calibrated["split"],
        "selection": {
            "selector": args.selector,
            "margin": selected["margin"],
            "selection_scores": selected["selection_scores"],
            "calibration_overall": selected["overall"],
            "calibration_group_metrics": selected["group_metrics"],
            "calibration_coupling_counts": selected["coupling_counts"],
        },
        "calibration_sweep": calibration_sweep,
        "same_split_controls": {
            "baseline_direction_aware": baseline_eval_metrics,
            "bucket_router": router_eval_metrics,
        },
        "eval": eval_metrics,
    }
    write_json(args.json_output, report)
    if args.predictions_output:
        write_jsonl(args.predictions_output, coupled_eval_rows)
    if args.md_output:
        output = Path(args.md_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_pair_coupled_markdown(report), encoding="utf-8")
    print(json.dumps({"selected": report["selection"], "eval": report["eval"]["overall"], "group": report["eval"]["group_metrics"]}, indent=2))


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.analyze_primevul_router_statistics import (
    bootstrap_delta,
    bootstrap_metric,
    exact_sign_test,
    group_metric_values,
    route_eval_rows,
)
from vrf.io_utils import read_json, read_jsonl, write_json


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Pair-Coupled Router Statistics",
        "",
        "This report compares the validation-selected bucket router against pair-coupled decoding on the same held-out pair groups.",
        "",
        "## Bootstrap 95% Confidence Intervals",
        "",
        "| system | metric | observed | ci95_low | ci95_high | units |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for system_name in ["bucket_router", "pair_coupled"]:
        for metric_name, row in payload["bootstrap"][system_name].items():
            lines.append(
                f"| {system_name} | {metric_name} | {row['observed']} | {row['ci95_low']} | {row['ci95_high']} | {row['units']} |"
            )
    lines.extend(
        [
            "",
            "## Pair-Coupled Minus Bucket Router",
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
            "Pair-coupled decoding changes discrete labels but not probability ordering, so orientation is expected to remain unchanged. Its value is in enforcing one positive and one negative decision inside paired groups, which directly targets group all-correct and row-level consistency.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap pair-coupled router gains over the validation-selected bucket router.")
    parser.add_argument("--calibrated-report", default="reports/secure_code_primevul_directional_bucket_router_calibrated_v1_report.json")
    parser.add_argument("--pair-coupled-predictions", default="outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl")
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    args = parser.parse_args()

    calibrated = read_json(args.calibrated_report)
    _, bucket_router_rows = route_eval_rows(calibrated)
    pair_coupled_rows = read_jsonl(args.pair_coupled_predictions)
    bucket_values = group_metric_values(bucket_router_rows)
    pair_coupled_values = group_metric_values(pair_coupled_rows)
    metrics = ["group_all_correct", "orientation"]
    payload: dict[str, Any] = {
        "calibrated_report": args.calibrated_report,
        "pair_coupled_predictions": args.pair_coupled_predictions,
        "iterations": args.iterations,
        "seed": args.seed,
        "bootstrap": {
            "bucket_router": {
                metric: bootstrap_metric(bucket_values, metric=metric, iterations=args.iterations, seed=args.seed)
                for metric in metrics
            },
            "pair_coupled": {
                metric: bootstrap_metric(pair_coupled_values, metric=metric, iterations=args.iterations, seed=args.seed)
                for metric in metrics
            },
        },
        "delta": {
            metric: bootstrap_delta(
                bucket_values,
                pair_coupled_values,
                metric=metric,
                iterations=args.iterations,
                seed=args.seed,
            )
            for metric in metrics
        },
        "sign_tests": {
            metric: exact_sign_test(bucket_values, pair_coupled_values, metric=metric)
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

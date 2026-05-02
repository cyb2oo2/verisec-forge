from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.evaluate_primevul_pair_side_correction import build_report, parse_floats
from vrf.io_utils import read_jsonl, write_json


def parse_ints(value: str) -> list[int]:
    parsed = [int(part.strip()) for part in value.split(",") if part.strip()]
    if not parsed:
        raise ValueError("At least one seed is required")
    return parsed


def mean(values: list[float]) -> float:
    return round(statistics.mean(values), 4) if values else 0.0


def stdev(values: list[float]) -> float:
    return round(statistics.stdev(values), 4) if len(values) > 1 else 0.0


def delta(row: dict[str, Any], metric: str) -> float:
    return round(row["eval"]["corrected"][metric] - row["eval"]["baseline"][metric], 4)


def summarize(seed_reports: list[dict[str, Any]]) -> dict[str, Any]:
    balanced_deltas = [delta(row, "balanced_accuracy") for row in seed_reports]
    group_deltas = [delta(row, "group_all_correct_rate") for row in seed_reports]
    gated_groups = [row["eval"]["gated_groups"] for row in seed_reports]
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
            "mean": mean([float(value) for value in gated_groups]),
            "min": min(gated_groups) if gated_groups else 0,
            "max": max(gated_groups) if gated_groups else 0,
        },
    }


def compact_report(seed: int, report: dict[str, Any]) -> dict[str, Any]:
    baseline = report["eval"]["baseline_pair_coupled"]
    corrected = report["eval"]["corrected"]
    return {
        "seed": seed,
        "selected_threshold": report["calibration"]["selection"]["threshold"],
        "eval": {
            "baseline": {
                "balanced_accuracy": baseline["overall"]["balanced_accuracy"],
                "group_all_correct_rate": baseline["group_metrics"]["group_all_correct_rate"],
                "orientation_accuracy": baseline["group_metrics"]["orientation_accuracy"],
                "fp": baseline["overall"]["fp"],
                "fn": baseline["overall"]["fn"],
            },
            "corrected": {
                "balanced_accuracy": corrected["overall"]["balanced_accuracy"],
                "group_all_correct_rate": corrected["group_metrics"]["group_all_correct_rate"],
                "orientation_accuracy": corrected["group_metrics"]["orientation_accuracy"],
                "fp": corrected["overall"]["fp"],
                "fn": corrected["overall"]["fn"],
            },
            "gated_groups": corrected["gate_counts"]["gated_groups"],
            "gated_rows": corrected["gate_counts"]["gated_rows"],
        },
    }


def build_multisplit_report(
    rows: list[dict[str, Any]],
    *,
    seeds: list[int],
    calibration_fraction: float,
    epochs: int,
    learning_rate: float,
    l2: float,
    thresholds: list[float],
    selector: str,
) -> dict[str, Any]:
    seed_reports = []
    for seed in seeds:
        report, _ = build_report(
            rows,
            calibration_fraction=calibration_fraction,
            seed=seed,
            epochs=epochs,
            learning_rate=learning_rate,
            l2=l2,
            thresholds=thresholds,
            selector=selector,
        )
        seed_reports.append(compact_report(seed, report))
    return {
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


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# PrimeVul Pair-Side Correction Multi-Split",
        "",
        "This report repeats the lightweight pair-side correction gate across pair-key calibration/eval splits. It checks whether the correction signal is stable enough to justify a training follow-up.",
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
        base = row["eval"]["baseline"]
        corr = row["eval"]["corrected"]
        lines.append(
            "| "
            + " | ".join(
                [
                    str(row["seed"]),
                    str(row["selected_threshold"]),
                    str(base["balanced_accuracy"]),
                    str(corr["balanced_accuracy"]),
                    str(round(corr["balanced_accuracy"] - base["balanced_accuracy"], 4)),
                    str(base["group_all_correct_rate"]),
                    str(corr["group_all_correct_rate"]),
                    str(round(corr["group_all_correct_rate"] - base["group_all_correct_rate"], 4)),
                    str(row["eval"]["gated_groups"]),
                    str(corr["fp"] - base["fp"]),
                    str(corr["fn"] - base["fn"]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "If deltas are not consistently positive, the current cheap gate should be treated as a diagnostic baseline rather than a deployable correction layer. The confident inversion set remains useful, but stronger features or an explicit contrastive model are needed.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run multi-split analysis for PrimeVul pair-side correction gate.")
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--seeds", default="7,13,42,99,123")
    parser.add_argument("--calibration-fraction", type=float, default=0.3)
    parser.add_argument("--epochs", type=int, default=80)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--l2", type=float, default=0.0001)
    parser.add_argument("--thresholds", default="0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9")
    parser.add_argument("--selector", default="balanced_accuracy", choices=["balanced_accuracy", "group_all_correct_rate"])
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    args = parser.parse_args()

    payload = build_multisplit_report(
        read_jsonl(args.predictions),
        seeds=parse_ints(args.seeds),
        calibration_fraction=args.calibration_fraction,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        l2=args.l2,
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

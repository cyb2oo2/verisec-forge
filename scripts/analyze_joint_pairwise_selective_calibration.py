from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_json


def parse_numbers(value: str, cast: type = float) -> list[Any]:
    return [cast(part.strip()) for part in value.split(",") if part.strip()]


def split_rows(
    rows: list[dict[str, Any]],
    *,
    calibration_fraction: float,
    seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    keys = sorted(str(row["pair_key"]) for row in rows)
    random.Random(seed).shuffle(keys)
    calibration_count = max(1, min(len(keys) - 1, round(len(keys) * calibration_fraction)))
    calibration_keys = set(keys[:calibration_count])
    return (
        [row for row in rows if str(row["pair_key"]) in calibration_keys],
        [row for row in rows if str(row["pair_key"]) not in calibration_keys],
    )


def clipped_logit(probability: float) -> float:
    probability = min(max(float(probability), 1e-6), 1.0 - 1e-6)
    return math.log(probability / (1.0 - probability))


def raw_margin(row: dict[str, Any]) -> float:
    return abs(float(row["vulnerable_candidate_probability"]) - float(row["safe_candidate_probability"]))


def correctness_confidence(row: dict[str, Any], *, temperature: float) -> float:
    safe_logit = clipped_logit(float(row["safe_candidate_probability"]))
    vulnerable_logit = clipped_logit(float(row["vulnerable_candidate_probability"]))
    magnitude = abs(vulnerable_logit - safe_logit) / temperature
    return 1.0 / (1.0 + math.exp(-min(magnitude, 50.0)))


def negative_log_likelihood(rows: list[dict[str, Any]], *, temperature: float) -> float:
    losses = []
    for row in rows:
        confidence = min(max(correctness_confidence(row, temperature=temperature), 1e-9), 1.0 - 1e-9)
        correct = bool(row["correct_orientation"])
        losses.append(-math.log(confidence if correct else 1.0 - confidence))
    return statistics.mean(losses)


def select_temperature(rows: list[dict[str, Any]], temperatures: list[float]) -> dict[str, float]:
    candidates = [
        {"temperature": temperature, "nll": negative_log_likelihood(rows, temperature=temperature)}
        for temperature in temperatures
    ]
    return min(candidates, key=lambda row: (row["nll"], row["temperature"]))


def expected_calibration_error(
    rows: list[dict[str, Any]],
    *,
    temperature: float,
    bins: int = 10,
) -> float:
    weighted_error = 0.0
    for index in range(bins):
        lower = index / bins
        upper = (index + 1) / bins
        bucket = []
        for row in rows:
            confidence = correctness_confidence(row, temperature=temperature)
            if lower <= confidence < upper or (index == bins - 1 and confidence == 1.0):
                bucket.append((confidence, float(bool(row["correct_orientation"]))))
        if bucket:
            mean_confidence = statistics.mean(value[0] for value in bucket)
            mean_accuracy = statistics.mean(value[1] for value in bucket)
            weighted_error += len(bucket) / len(rows) * abs(mean_confidence - mean_accuracy)
    return weighted_error


def calibration_metrics(rows: list[dict[str, Any]], *, temperature: float) -> dict[str, float]:
    confidences = [correctness_confidence(row, temperature=temperature) for row in rows]
    labels = [float(bool(row["correct_orientation"])) for row in rows]
    return {
        "temperature": temperature,
        "nll": negative_log_likelihood(rows, temperature=temperature),
        "brier": statistics.mean((confidence - label) ** 2 for confidence, label in zip(confidences, labels, strict=True)),
        "ece_10": expected_calibration_error(rows, temperature=temperature),
    }


def selective_metrics(rows: list[dict[str, Any]], *, margin: float) -> dict[str, Any]:
    accepted = [row for row in rows if raw_margin(row) >= margin]
    abstained = [row for row in rows if raw_margin(row) < margin]
    total_errors = sum(not bool(row["correct_orientation"]) for row in rows)
    accepted_errors = sum(not bool(row["correct_orientation"]) for row in accepted)
    abstained_errors = sum(not bool(row["correct_orientation"]) for row in abstained)
    return {
        "margin": margin,
        "pairs": len(rows),
        "accepted": len(accepted),
        "abstained": len(abstained),
        "coverage": len(accepted) / len(rows),
        "accepted_accuracy": (
            sum(bool(row["correct_orientation"]) for row in accepted) / len(accepted) if accepted else None
        ),
        "selective_risk": accepted_errors / len(accepted) if accepted else None,
        "accepted_errors": accepted_errors,
        "abstained_errors": abstained_errors,
        "error_capture_rate": abstained_errors / total_errors if total_errors else 0.0,
    }


def select_margin(
    rows: list[dict[str, Any]],
    *,
    margins: list[float],
    minimum_coverage: float,
) -> dict[str, Any]:
    candidates = [selective_metrics(rows, margin=margin) for margin in margins]
    eligible = [row for row in candidates if row["coverage"] >= minimum_coverage and row["accepted"]]
    if not eligible:
        raise ValueError(f"No margin satisfies minimum coverage {minimum_coverage}")
    selected = max(
        eligible,
        key=lambda row: (
            float(row["accepted_accuracy"]),
            row["coverage"],
            -row["margin"],
        ),
    )
    return {"selected": selected, "candidates": candidates}


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "mean": statistics.mean(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
    }


def evaluate_seed(
    rows: list[dict[str, Any]],
    *,
    seed: int,
    calibration_fraction: float,
    temperatures: list[float],
    margins: list[float],
    minimum_coverage: float,
) -> dict[str, Any]:
    calibration_rows, eval_rows = split_rows(
        rows,
        calibration_fraction=calibration_fraction,
        seed=seed,
    )
    temperature = select_temperature(calibration_rows, temperatures)
    margin_selection = select_margin(
        calibration_rows,
        margins=margins,
        minimum_coverage=minimum_coverage,
    )
    selected_margin = float(margin_selection["selected"]["margin"])
    baseline = selective_metrics(eval_rows, margin=0.0)
    selective = selective_metrics(eval_rows, margin=selected_margin)
    return {
        "seed": seed,
        "split": {
            "calibration_pairs": len(calibration_rows),
            "eval_pairs": len(eval_rows),
        },
        "selection": {
            "minimum_calibration_coverage": minimum_coverage,
            "temperature": temperature,
            "margin": selected_margin,
            "margin_calibration_metrics": margin_selection["selected"],
        },
        "eval": {
            "baseline": baseline,
            "selective": selective,
            "raw_calibration": calibration_metrics(eval_rows, temperature=1.0),
            "temperature_calibrated": calibration_metrics(
                eval_rows,
                temperature=float(temperature["temperature"]),
            ),
        },
    }


def build_summary(seed_reports: list[dict[str, Any]]) -> dict[str, Any]:
    fields = {
        "baseline_accuracy": [row["eval"]["baseline"]["accepted_accuracy"] for row in seed_reports],
        "selective_coverage": [row["eval"]["selective"]["coverage"] for row in seed_reports],
        "selective_accuracy": [row["eval"]["selective"]["accepted_accuracy"] for row in seed_reports],
        "selective_error_capture_rate": [row["eval"]["selective"]["error_capture_rate"] for row in seed_reports],
        "raw_nll": [row["eval"]["raw_calibration"]["nll"] for row in seed_reports],
        "calibrated_nll": [row["eval"]["temperature_calibrated"]["nll"] for row in seed_reports],
        "raw_brier": [row["eval"]["raw_calibration"]["brier"] for row in seed_reports],
        "calibrated_brier": [row["eval"]["temperature_calibrated"]["brier"] for row in seed_reports],
        "raw_ece_10": [row["eval"]["raw_calibration"]["ece_10"] for row in seed_reports],
        "calibrated_ece_10": [row["eval"]["temperature_calibrated"]["ece_10"] for row in seed_reports],
    }
    return {name: summarize([float(value) for value in values]) for name, values in fields.items()}


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Learned Joint Pairwise Selective Calibration",
        "",
        "This analysis preserves the pair-head direction rule and calibrates only confidence and abstention. "
        "A non-zero direction threshold is intentionally not tuned because the stored prediction rows are "
        "gold-aligned by class; tuning that threshold would leak target ordering.",
        "",
        "## Protocol",
        "",
        f"- pair-key split seeds: `{','.join(str(seed) for seed in payload['seeds_requested'])}`",
        f"- calibration fraction: `{payload['calibration_fraction']}`",
        f"- minimum calibration coverage: `{payload['minimum_coverage']}`",
        "- margin selection: highest calibration accepted accuracy subject to minimum coverage",
        "- temperature selection: lowest calibration correctness NLL",
        "- held-out reporting: coverage, accepted accuracy, error capture, NLL, Brier, and ECE",
        "",
        "## Multi-Split Summary",
        "",
        "| metric | mean | stdev | min | max |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name, summary in payload["summary"].items():
        lines.append(
            f"| {name} | {summary['mean']:.4f} | {summary['stdev']:.4f} | "
            f"{summary['min']:.4f} | {summary['max']:.4f} |"
        )
    lines.extend(
        [
            "",
            "## Per-Split Results",
            "",
            "| seed | temperature | margin | baseline acc | coverage | accepted acc | error capture | raw ECE | calibrated ECE |",
            "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in payload["seeds"]:
        lines.append(
            f"| {row['seed']} | {row['selection']['temperature']['temperature']} | "
            f"{row['selection']['margin']} | {row['eval']['baseline']['accepted_accuracy']:.4f} | "
            f"{row['eval']['selective']['coverage']:.4f} | "
            f"{row['eval']['selective']['accepted_accuracy']:.4f} | "
            f"{row['eval']['selective']['error_capture_rate']:.4f} | "
            f"{row['eval']['raw_calibration']['ece_10']:.4f} | "
            f"{row['eval']['temperature_calibrated']['ece_10']:.4f} |"
        )
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "Selective accuracy is conditional on abstaining from low-margin pairs and is not a replacement for "
            "full-coverage orientation accuracy. Temperature scaling changes confidence calibration only; it "
            "does not change pair decisions.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Calibrate confidence and abstention for learned pairwise predictions.")
    parser.add_argument(
        "--predictions",
        default="outputs/secure_code_primevul_joint_pairwise_qwen15b_lora_v1_predictions.jsonl",
    )
    parser.add_argument("--seeds", default="7,13,42,99,123")
    parser.add_argument("--calibration-fraction", type=float, default=0.3)
    parser.add_argument("--minimum-coverage", type=float, default=0.8)
    parser.add_argument("--margins", default="0,0.01,0.02,0.03,0.04,0.05,0.075,0.1,0.15,0.2")
    parser.add_argument("--temperatures", default="0.5,0.75,1,1.25,1.5,2,3,4,6,8")
    parser.add_argument(
        "--json-output",
        default="reports/secure_code_primevul_joint_pairwise_selective_calibration_v1.json",
    )
    parser.add_argument(
        "--md-output",
        default="reports/PRIMEVUL_JOINT_PAIRWISE_SELECTIVE_CALIBRATION.md",
    )
    args = parser.parse_args()

    rows = read_jsonl(args.predictions)
    seeds = parse_numbers(args.seeds, int)
    margins = parse_numbers(args.margins)
    temperatures = parse_numbers(args.temperatures)
    seed_reports = [
        evaluate_seed(
            rows,
            seed=seed,
            calibration_fraction=args.calibration_fraction,
            temperatures=temperatures,
            margins=margins,
            minimum_coverage=args.minimum_coverage,
        )
        for seed in seeds
    ]
    payload = {
        "status": "ok",
        "method": "pair_key_heldout_selective_calibration",
        "predictions": args.predictions,
        "seeds_requested": seeds,
        "calibration_fraction": args.calibration_fraction,
        "minimum_coverage": args.minimum_coverage,
        "candidate_margins": margins,
        "candidate_temperatures": temperatures,
        "summary": build_summary(seed_reports),
        "seeds": seed_reports,
        "claim_boundary": (
            "Accepted accuracy is conditional on abstention. Direction thresholds remain fixed to preserve "
            "swap-equivariant pair decisions and avoid gold-order leakage."
        ),
    }
    write_json(args.json_output, payload)
    output = Path(args.md_output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()

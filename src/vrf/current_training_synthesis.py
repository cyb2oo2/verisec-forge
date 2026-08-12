from __future__ import annotations

import math
import statistics
from typing import Any, Mapping


# Two-sided 95% Student-t critical values. The table is sufficient for the
# small-seed precision analysis; 1.96 is used beyond 30 degrees of freedom.
T95 = {
    1: 12.706,
    2: 4.303,
    3: 3.182,
    4: 2.776,
    5: 2.571,
    6: 2.447,
    7: 2.365,
    8: 2.306,
    9: 2.262,
    10: 2.228,
    11: 2.201,
    12: 2.179,
    13: 2.160,
    14: 2.145,
    15: 2.131,
    16: 2.120,
    17: 2.110,
    18: 2.101,
    19: 2.093,
    20: 2.086,
    21: 2.080,
    22: 2.074,
    23: 2.069,
    24: 2.064,
    25: 2.060,
    26: 2.056,
    27: 2.052,
    28: 2.048,
    29: 2.045,
    30: 2.042,
}


def _t95(df: int) -> float:
    return T95.get(df, 1.96)


def _prose_population(payload: Mapping[str, Any], system: str) -> Mapping[str, Any]:
    return payload["families"]["prose"]["systems"][system]["population"]


def extract_seed_metrics(payload: Mapping[str, Any]) -> list[dict[str, float | int]]:
    """Extract the repository's conventional seed-7/seed-123 comparison."""

    rows = []
    for seed, system in ((7, "baseline_antisym"), (123, "repaired_antisym")):
        population = _prose_population(payload, system)
        rows.append(
            {
                "seed": seed,
                "concordant_accuracy": float(population["acc_concordant"]),
                "discordant_accuracy": float(population["acc_discordant"]),
                "balanced_accuracy": float(population["balanced_accuracy"]),
                "balanced_delta_vs_control": float(population["delta_vs_control"]),
            }
        )
    return rows


def summarize_seed_metric(values: list[float]) -> dict[str, Any]:
    if len(values) < 2:
        raise ValueError("seed summaries require at least two observations")
    mean = statistics.mean(values)
    standard_deviation = statistics.stdev(values)
    half_width = _t95(len(values) - 1) * standard_deviation / math.sqrt(len(values))
    return {
        "n_seeds": len(values),
        "mean": mean,
        "sample_standard_deviation": standard_deviation,
        "observed_min": min(values),
        "observed_max": max(values),
        "observed_range": max(values) - min(values),
        "student_t_95_ci": [mean - half_width, mean + half_width],
        "student_t_95_half_width": half_width,
    }


def required_seed_count(standard_deviation: float, target_half_width: float) -> int:
    if standard_deviation <= 0 or target_half_width <= 0:
        raise ValueError("standard deviation and target half-width must be positive")
    for n_seeds in range(2, 10_001):
        half_width = _t95(n_seeds - 1) * standard_deviation / math.sqrt(n_seeds)
        if half_width <= target_half_width:
            return n_seeds
    raise RuntimeError("required seed count exceeded search bound")


def build_current_training_synthesis(
    *,
    matched_compute_payloads: Mapping[str, Mapping[str, Any]],
    supply_payloads: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    matched_arms: list[dict[str, Any]] = []
    for backbone, payload in matched_compute_payloads.items():
        seeds = extract_seed_metrics(payload)
        discordant = [float(row["discordant_accuracy"]) for row in seeds]
        balanced_delta = [float(row["balanced_delta_vs_control"]) for row in seeds]
        matched_arms.append(
            {
                "backbone": backbone,
                "seeds": seeds,
                "discordant_accuracy": summarize_seed_metric(discordant),
                "balanced_delta_vs_control": summarize_seed_metric(balanced_delta),
            }
        )

    seven_b = next(arm["seeds"] for arm in matched_arms if "7B" in arm["backbone"])
    three_b = next(arm["seeds"] for arm in matched_arms if "3B" in arm["backbone"])
    closest_7b_3b_same_seed_gap = min(
        float(three_row["discordant_accuracy"])
        - float(seven_row["discordant_accuracy"])
        for seven_row, three_row in zip(seven_b, three_b, strict=True)
    )
    largest_matched_seed_range = max(
        arm["discordant_accuracy"]["observed_range"] for arm in matched_arms
    )

    supply_arms: list[dict[str, Any]] = []
    for training_set, payload in supply_payloads.items():
        seeds = extract_seed_metrics(payload)
        supply_arms.append(
            {
                "training_set": training_set,
                "seeds": seeds,
                "discordant_accuracy": summarize_seed_metric(
                    [float(row["discordant_accuracy"]) for row in seeds]
                ),
                "balanced_delta_vs_control": summarize_seed_metric(
                    [float(row["balanced_delta_vs_control"]) for row in seeds]
                ),
            }
        )

    supply_means = [
        arm["discordant_accuracy"]["mean"] for arm in supply_arms
    ]
    supply_ranges = [
        arm["discordant_accuracy"]["observed_range"] for arm in supply_arms
    ]
    largest_between_arm_gap = max(supply_means) - min(supply_means)
    smallest_within_arm_range = min(supply_ranges)
    largest_within_arm_range = max(supply_ranges)

    bf16_standard_deviations = [
        arm["discordant_accuracy"]["sample_standard_deviation"]
        for arm in matched_arms
        if "bf16" in arm["backbone"]
    ]
    conservative_sd = max(bf16_standard_deviations)
    third_seed_half_width = _t95(2) * conservative_sd / math.sqrt(3)

    return {
        "schema_version": 1,
        "status": "report_backed",
        "scope": "controlled_training_synthesis",
        "matched_compute": {
            "protocol": {
                "training_pairs": 2208,
                "epochs": 4,
                "optimizer_steps": 1104,
                "discordant_evaluation_pairs_per_seed": 180,
                "seeds": [7, 123],
            },
            "arms": matched_arms,
            "observed_ordering": "1.5B bf16 < 7B nf4 < 3B bf16 on both seeds",
            "closest_7b_3b_same_seed_gap": closest_7b_3b_same_seed_gap,
            "largest_within_arm_seed_range": largest_matched_seed_range,
            "claim": (
                "At matched data and optimizer steps, the observed two-seed system "
                "ordering is 1.5B bf16 < 7B nf4 < 3B bf16 on discordant pairs."
            ),
            "boundary": (
                "This is a two-seed, one-model-family system comparison. The 7B "
                "quantization regime is a precision confound. The closest same-seed "
                f"7B-to-3B gap ({closest_7b_3b_same_seed_gap:.4f}) is below the largest "
                f"within-arm seed range ({largest_matched_seed_range:.4f}). The zero "
                "observed 7B seed SD is not evidence of zero training variance."
            ),
        },
        "discordant_supply_control": {
            "protocol": {
                "backbone": "Qwen2.5-Coder-3B-Instruct bf16",
                "epochs": 4,
                "discordant_evaluation_pairs_per_seed": 180,
                "seeds": [7, 123],
            },
            "arms": supply_arms,
            "largest_between_arm_mean_gap": largest_between_arm_gap,
            "smallest_within_arm_seed_range": smallest_within_arm_range,
            "largest_within_arm_seed_range": largest_within_arm_range,
            "claim": (
                "Decontamination and mined discordant supply leave mean balanced "
                "delta nearly unchanged and move mean discordant accuracy only "
                "slightly across the three two-seed arms."
            ),
            "boundary": (
                f"The largest between-arm mean gap ({largest_between_arm_gap:.4f}) "
                f"is below the largest within-arm seed range ({largest_within_arm_range:.4f}) "
                f"but slightly above the smallest ({smallest_within_arm_range:.4f}); "
                "this two-seed control does not establish a data-supply improvement."
            ),
        },
        "seed_precision": {
            "method": "Student-t interval over independent training-seed observations",
            "unit_of_inference": "training seed",
            "conservative_planning_standard_deviation": conservative_sd,
            "basis": "maximum observed discordant-accuracy sample SD across the two bf16 matched-compute arms",
            "projected_95_half_width_at_3_seeds": third_seed_half_width,
            "required_seeds_for_95_half_width_at_most_0_05": required_seed_count(
                conservative_sd, 0.05
            ),
            "required_seeds_for_95_half_width_at_most_0_025": required_seed_count(
                conservative_sd, 0.025
            ),
            "interpretation": (
                "A third seed is a useful minimum diagnostic for direction and seed "
                "collisions, but is not sufficient for a sharp mean estimate. Pair-"
                "level binomial intervals are not substituted for seed uncertainty."
            ),
            "caution": (
                "Variance planning from two seeds is unstable; these counts are "
                "sensitivity calculations, not a preregistered power guarantee."
            ),
        },
        "overall_conclusion": (
            "The controlled training results are bounded experimental evidence for "
            "experimental design and shortcut diagnosis, but not evidence of a "
            "general secure-patch reasoning solution."
        ),
    }


def render_current_training_markdown(payload: Mapping[str, Any]) -> str:
    matched = payload["matched_compute"]
    supply = payload["discordant_supply_control"]
    precision = payload["seed_precision"]
    lines = [
        "# Current Controlled Training Synthesis",
        "",
        "> **Status: report-backed, bounded evidence.** This synthesis is rebuilt from",
        "> retained evaluator JSONs. It does not rerun training or promote a model.",
        "",
        "## Matched-compute backbone control",
        "",
        "| Backbone / precision | Seed 7 discordant | Seed 123 discordant | Mean | Seed SD |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for arm in matched["arms"]:
        values = arm["seeds"]
        summary = arm["discordant_accuracy"]
        lines.append(
            f"| {arm['backbone']} | `{values[0]['discordant_accuracy']:.4f}` | "
            f"`{values[1]['discordant_accuracy']:.4f}` | `{summary['mean']:.4f}` | "
            f"`{summary['sample_standard_deviation']:.4f}` |"
        )
    lines.extend(
        [
            "",
            matched["claim"],
            "",
            f"**Boundary.** {matched['boundary']}",
            "",
            "## Decontamination and discordant-supply control",
            "",
            "| Training set | Mean discordant | Mean balanced delta | Discordant seed range |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for arm in supply["arms"]:
        discordant = arm["discordant_accuracy"]
        delta = arm["balanced_delta_vs_control"]
        lines.append(
            f"| {arm['training_set']} | `{discordant['mean']:.4f}` | `{delta['mean']:.4f}` | "
            f"`{discordant['observed_range']:.4f}` |"
        )
    lines.extend(
        [
            "",
            supply["claim"],
            "",
            f"**Boundary.** {supply['boundary']}",
            "",
            "## Seed precision analysis",
            "",
            f"Using the larger observed bf16 seed SD (`{precision['conservative_planning_standard_deviation']:.4f}`), "
            f"a three-seed Student-t interval would still have a projected 95% half-width of "
            f"`{precision['projected_95_half_width_at_3_seeds']:.4f}`. A sensitivity calculation "
            f"requires **{precision['required_seeds_for_95_half_width_at_most_0_05']} seeds** for half-width "
            f"at most `0.05`, or **{precision['required_seeds_for_95_half_width_at_most_0_025']} seeds** for "
            "half-width at most `0.025`.",
            "",
            precision["interpretation"],
            "",
            f"**Caution.** {precision['caution']}",
            "",
            "## Claim boundary",
            "",
            payload["overall_conclusion"],
            "",
            "Machine-readable source: `reports/current_shortcut_resistant_training_synthesis_v1.json`.",
        ]
    )
    return "\n".join(lines) + "\n"

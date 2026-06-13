from __future__ import annotations

import random
from statistics import mean
from typing import Any, Callable


def compare_readouts(
    control_records: list[dict[str, Any]],
    candidate_records: list[dict[str, Any]],
    *,
    iterations: int = 2000,
    seed: int = 42,
) -> dict[str, Any]:
    control = {
        (row["dataset"], row["pair_key"]): row
        for row in control_records
    }
    candidate = {
        (row["dataset"], row["pair_key"]): row
        for row in candidate_records
    }
    if control.keys() != candidate.keys():
        raise ValueError("readout records must use identical pair keys")
    paired = [
        {"control": control[key], "candidate": candidate[key]}
        for key in sorted(control)
    ]
    return {
        "all_pairs": _summary(
            paired,
            iterations=iterations,
            seed=seed,
        ),
        "jointly_clean": _summary(
            [
                row
                for row in paired
                if row["control"]["all_visible"]
                and row["candidate"]["all_visible"]
            ],
            iterations=iterations,
            seed=seed + 101,
        ),
        "by_dataset": {
            dataset: _summary(
                [
                    row
                    for row in paired
                    if row["control"]["dataset"] == dataset
                ],
                iterations=iterations,
                seed=seed + 1000 + index * 101,
            )
            for index, dataset in enumerate(
                sorted({row["control"]["dataset"] for row in paired})
            )
        },
    }


def _summary(
    rows: list[dict[str, Any]],
    *,
    iterations: int,
    seed: int,
) -> dict[str, Any]:
    if not rows:
        return {"pairs": 0}
    metrics: dict[str, Callable[[dict[str, Any]], float]] = {
        "canonical_accuracy_delta": lambda row: float(
            row["candidate"]["canonical_correct"]
        )
        - float(row["control"]["canonical_correct"]),
        "post_diff_relation_delta": lambda row: float(
            row["candidate"]["post_diff_relation"]
        )
        - float(row["control"]["post_diff_relation"]),
        "side_swap_relation_delta": lambda row: float(
            row["candidate"]["side_swap_relation"]
        )
        - float(row["control"]["side_swap_relation"]),
        "robust_success_delta": lambda row: float(
            row["candidate"]["robust_success"]
        )
        - float(row["control"]["robust_success"]),
    }
    rng = random.Random(seed)
    result: dict[str, Any] = {"pairs": len(rows)}
    for name, metric in metrics.items():
        estimate = mean(metric(row) for row in rows)
        samples = []
        for _ in range(iterations):
            sample = [rows[rng.randrange(len(rows))] for _ in rows]
            samples.append(mean(metric(row) for row in sample))
        result[name] = {
            "estimate": estimate,
            "ci95": _percentile_interval(samples),
        }
    return result


def _percentile_interval(values: list[float]) -> list[float]:
    ordered = sorted(values)
    low = ordered[int(0.025 * (len(ordered) - 1))]
    high = ordered[int(0.975 * (len(ordered) - 1))]
    return [low, high]

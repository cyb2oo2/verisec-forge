from __future__ import annotations

import random
from statistics import mean
from typing import Any


SUFFIX_VARIANTS = (
    "confirm_suffix_short_v1",
    "confirm_suffix_medium_v1",
    "confirm_suffix_long_v1",
)


def summarize_confirmatory_rows(
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    grouped: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    for row in rows:
        key = (str(row["dataset"]), str(row["pair_key"]))
        grouped.setdefault(key, {})[str(row["audit_variant"])] = row
    records = []
    for (dataset, pair_key), group in sorted(grouped.items()):
        required = ("canonical", "side_swap", *SUFFIX_VARIANTS)
        if not all(name in group for name in required):
            continue
        canonical = group["canonical"]
        canonical_prediction = str(canonical["predicted_riskier_side"])
        suffix_relations = {
            name: (
                str(group[name]["predicted_riskier_side"])
                == canonical_prediction
            )
            for name in SUFFIX_VARIANTS
        }
        suffix_visible = {
            name: (
                group[name]["runtime_accounting"][
                    "transformation_tokens_visible"
                ]
                > 0
            )
            for name in SUFFIX_VARIANTS
        }
        records.append(
            {
                "dataset": dataset,
                "pair_key": pair_key,
                "canonical_correct": canonical_prediction
                == str(canonical["gold_riskier_side"]),
                "canonical_prediction": canonical_prediction,
                "side_swap_prediction": str(
                    group["side_swap"]["predicted_riskier_side"]
                ),
                "side_swap_correct": str(
                    group["side_swap"]["predicted_riskier_side"]
                )
                == str(group["side_swap"]["gold_riskier_side"]),
                "side_swap_relation": str(
                    group["side_swap"]["predicted_riskier_side"]
                )
                != canonical_prediction,
                "suffix_relations": suffix_relations,
                "suffix_visible": suffix_visible,
                "all_suffix_visible": all(suffix_visible.values()),
                "hunk_clean": all(
                    not group[name]["runtime_accounting"][
                        "critical_hunk_truncated"
                    ]
                    for name in required
                ),
                "pooling_fallback": any(
                    bool(group[name].get("pooling_fallback", False))
                    for name in required
                ),
            }
        )
    side_swap_equivariance = _mean_bool(
        row["side_swap_relation"] for row in records
    )
    side_swap_independence_baseline = _independence_baseline(records)
    return {
        "pairs": len(records),
        "canonical_accuracy": _mean_bool(
            row["canonical_correct"] for row in records
        ),
        "side_swap_equivariance": side_swap_equivariance,
        "side_swap_independence_baseline": side_swap_independence_baseline,
        "side_swap_equivariance_residual": (
            side_swap_equivariance - side_swap_independence_baseline
        ),
        "both_directions_correct": _mean_bool(
            row["canonical_correct"] and row["side_swap_correct"]
            for row in records
        ),
        "raw_suffix_consistency": {
            name: _mean_bool(
                row["suffix_relations"][name] for row in records
            )
            for name in SUFFIX_VARIANTS
        },
        "suffix_consistency": {
            name: _mean_bool(
                row["suffix_relations"][name]
                for row in records
                if row["suffix_visible"][name]
            )
            for name in SUFFIX_VARIANTS
        },
        "raw_macro_suffix_consistency": mean(
            mean(float(value) for value in row["suffix_relations"].values())
            for row in records
        ),
        "macro_suffix_consistency": mean(
            _macro_suffix(row)
            for row in records
            if any(row["suffix_visible"].values())
        ),
        "suffix_visible_pair_coverage": _mean_bool(
            any(row["suffix_visible"].values()) for row in records
        ),
        "all_suffix_visible_pair_coverage": _mean_bool(
            row["all_suffix_visible"] for row in records
        ),
        "hunk_clean_pair_coverage": _mean_bool(
            row["hunk_clean"] for row in records
        ),
        "pooling_fallback_rate": _mean_bool(
            row["pooling_fallback"] for row in records
        ),
        "records": records,
    }


def compare_confirmatory_models(
    control_by_seed: dict[int, list[dict[str, Any]]],
    candidate_by_seed: dict[int, list[dict[str, Any]]],
    *,
    iterations: int = 5000,
    seed: int = 20260613,
) -> dict[str, Any]:
    common_seeds = sorted(set(control_by_seed) & set(candidate_by_seed))
    if not common_seeds:
        raise ValueError("no common confirmatory seeds")
    per_seed = {
        str(run_seed): _paired_delta_summary(
            control_by_seed[run_seed],
            candidate_by_seed[run_seed],
            iterations=iterations,
            seed=seed + run_seed,
        )
        for run_seed in common_seeds
    }
    pooled = _pooled_pair_summary(
        control_by_seed,
        candidate_by_seed,
        seeds=common_seeds,
        iterations=iterations,
        seed=seed,
    )
    datasets = sorted(
        {
            str(row["dataset"])
            for rows in control_by_seed.values()
            for row in rows
        }
    )
    by_dataset = {}
    for index, dataset in enumerate(datasets):
        control_subset = {
            run_seed: [
                row
                for row in control_by_seed[run_seed]
                if str(row["dataset"]) == dataset
            ]
            for run_seed in common_seeds
        }
        candidate_subset = {
            run_seed: [
                row
                for row in candidate_by_seed[run_seed]
                if str(row["dataset"]) == dataset
            ]
            for run_seed in common_seeds
        }
        by_dataset[dataset] = _pooled_pair_summary(
            control_subset,
            candidate_subset,
            seeds=common_seeds,
            iterations=iterations,
            seed=seed + (index + 1) * 1009,
        )
    canonical_low = pooled["canonical_accuracy_delta"]["ci95"][0]
    suffix_low = pooled["macro_suffix_consistency_delta"]["ci95"][0]
    checks = {
        "macro_suffix_ci_lower_gt_zero": suffix_low > 0,
        "canonical_noninferiority_ci_lower_gte_minus_0_02": (
            canonical_low >= -0.02
        ),
        "all_seed_suffix_deltas_positive": all(
            row["macro_suffix_consistency_delta"]["estimate"] > 0
            for row in per_seed.values()
        ),
    }
    return {
        "seeds": common_seeds,
        "per_seed": per_seed,
        "pooled_pair_cluster": pooled,
        "by_dataset": by_dataset,
        "success_rule": {**checks, "confirmed": all(checks.values())},
    }


def _paired_delta_summary(
    control_records: list[dict[str, Any]],
    candidate_records: list[dict[str, Any]],
    *,
    iterations: int,
    seed: int,
) -> dict[str, Any]:
    paired = _align(control_records, candidate_records)
    return _bootstrap_summary(paired, iterations=iterations, seed=seed)


def _pooled_pair_summary(
    control_by_seed: dict[int, list[dict[str, Any]]],
    candidate_by_seed: dict[int, list[dict[str, Any]]],
    *,
    seeds: list[int],
    iterations: int,
    seed: int,
) -> dict[str, Any]:
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for run_seed in seeds:
        for row in _align(
            control_by_seed[run_seed],
            candidate_by_seed[run_seed],
        ):
            key = (
                str(row["control"]["dataset"]),
                str(row["control"]["pair_key"]),
            )
            by_key.setdefault(key, []).append(row)
    pooled = []
    for key, rows in sorted(by_key.items()):
        pooled.append(
            {
                "control": rows[0]["control"],
                "candidate": rows[0]["candidate"],
                "canonical_delta": mean(
                    float(row["candidate"]["canonical_correct"])
                    - float(row["control"]["canonical_correct"])
                    for row in rows
                ),
                "suffix_delta": mean(
                    _macro_suffix(row["candidate"])
                    - _macro_suffix(row["control"])
                    for row in rows
                ),
                "suffix_visible": any(
                    any(run["control"]["suffix_visible"].values())
                    for run in rows
                )
                and any(
                    any(run["candidate"]["suffix_visible"].values())
                    for run in rows
                ),
            }
        )
    return _bootstrap_summary(
        pooled,
        iterations=iterations,
        seed=seed,
        precomputed=True,
    )


def _align(
    control_records: list[dict[str, Any]],
    candidate_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    control = {
        (row["dataset"], row["pair_key"]): row for row in control_records
    }
    candidate = {
        (row["dataset"], row["pair_key"]): row
        for row in candidate_records
    }
    if control.keys() != candidate.keys():
        raise ValueError("confirmatory records must use identical pair keys")
    return [
        {"control": control[key], "candidate": candidate[key]}
        for key in sorted(control)
    ]


def _bootstrap_summary(
    paired: list[dict[str, Any]],
    *,
    iterations: int,
    seed: int,
    precomputed: bool = False,
) -> dict[str, Any]:
    def canonical_delta(row):
        if precomputed:
            return row["canonical_delta"]
        return float(row["candidate"]["canonical_correct"]) - float(
            row["control"]["canonical_correct"]
        )

    def suffix_delta(row):
        if precomputed:
            return row["suffix_delta"]
        return _macro_suffix(row["candidate"]) - _macro_suffix(row["control"])

    def suffix_visible(row):
        if precomputed:
            return bool(row["suffix_visible"])
        return any(row["control"]["suffix_visible"].values()) and any(
            row["candidate"]["suffix_visible"].values()
        )

    suffix_paired = [row for row in paired if suffix_visible(row)]
    if not paired or not suffix_paired:
        raise ValueError("confirmatory comparison requires visible suffix pairs")
    canonical = mean(canonical_delta(row) for row in paired)
    suffix = mean(suffix_delta(row) for row in suffix_paired)
    rng = random.Random(seed)
    canonical_samples = []
    suffix_samples = []
    for _ in range(iterations):
        canonical_sample = [
            paired[rng.randrange(len(paired))] for _ in paired
        ]
        suffix_sample = [
            suffix_paired[rng.randrange(len(suffix_paired))]
            for _ in suffix_paired
        ]
        canonical_samples.append(
            mean(canonical_delta(row) for row in canonical_sample)
        )
        suffix_samples.append(
            mean(suffix_delta(row) for row in suffix_sample)
        )
    return {
        "canonical_pairs": len(paired),
        "suffix_visible_pairs": len(suffix_paired),
        "canonical_accuracy_delta": {
            "estimate": canonical,
            "ci95": _percentile(canonical_samples),
        },
        "macro_suffix_consistency_delta": {
            "estimate": suffix,
            "ci95": _percentile(suffix_samples),
        },
    }


def _macro_suffix(row: dict[str, Any]) -> float:
    visible = [
        float(row["suffix_relations"][name])
        for name in SUFFIX_VARIANTS
        if row["suffix_visible"][name]
    ]
    return mean(visible) if visible else 0.0


def _independence_baseline(records: list[dict[str, Any]]) -> float:
    canonical_b = _mean_bool(
        row["canonical_prediction"] == "B" for row in records
    )
    swap_b = _mean_bool(
        row["side_swap_prediction"] == "B" for row in records
    )
    return canonical_b * (1.0 - swap_b) + (1.0 - canonical_b) * swap_b


def _mean_bool(values) -> float:
    values = list(values)
    return sum(bool(value) for value in values) / len(values)


def _percentile(values: list[float]) -> list[float]:
    ordered = sorted(values)
    return [
        ordered[int(0.025 * (len(ordered) - 1))],
        ordered[int(0.975 * (len(ordered) - 1))],
    ]

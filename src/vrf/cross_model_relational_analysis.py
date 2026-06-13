from __future__ import annotations

import random
from statistics import mean
from typing import Any

from vrf.qwen_mechanism_analysis import analyze_length


REQUIRED_VARIANTS = (
    "canonical",
    "side_swap",
    "canonical_no_metadata",
    "padding_pre_diff",
    "padding_post_diff",
    "padding_post_diff_terminal_phrase",
)


def summarize_model(
    rows: list[dict[str, Any]],
    *,
    model_metadata: dict[str, Any],
    max_length: int,
) -> dict[str, Any]:
    report = analyze_length(rows, max_length=max_length)
    variants = report["variants"]
    grouped: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    for row in rows:
        key = (str(row["dataset"]), str(row["pair_key"]))
        grouped.setdefault(key, {})[str(row["audit_variant"])] = row

    robust = 0
    clean_and_robust = 0
    clean_pairs = 0
    complete = 0
    pair_records = []
    for group in grouped.values():
        if not all(variant in group for variant in REQUIRED_VARIANTS):
            continue
        complete += 1
        canonical = group["canonical"]
        canonical_prediction = str(canonical["predicted_riskier_side"])
        correct = canonical_prediction == str(canonical["gold_riskier_side"])
        relations = []
        for variant in REQUIRED_VARIANTS[1:]:
            transformed = group[variant]
            if transformed["expected_relation"] == "equivariant_swap":
                relations.append(
                    transformed["predicted_riskier_side"]
                    != canonical_prediction
                )
            else:
                relations.append(
                    transformed["predicted_riskier_side"]
                    == canonical_prediction
                )
        success = correct and all(relations)
        robust += success
        all_visible = all(
            not row["runtime_accounting"]["critical_hunk_truncated"]
            for row in group.values()
        )
        clean_pairs += all_visible
        clean_and_robust += success and all_visible
        pair_records.append(
            {
                "dataset": str(canonical["dataset"]),
                "pair_key": str(canonical["pair_key"]),
                "canonical_correct": correct,
                "canonical_confidence": float(canonical["confidence"]),
                "canonical_prediction": canonical_prediction,
                "canonical_gold": str(canonical["gold_riskier_side"]),
                "side_swap_prediction": str(
                    group["side_swap"]["predicted_riskier_side"]
                ),
                "side_swap_gold": str(
                    group["side_swap"]["gold_riskier_side"]
                ),
                "side_swap_relation": (
                    group["side_swap"]["predicted_riskier_side"]
                    != canonical_prediction
                ),
                "training_prompt_prediction": str(
                    group["training_prompt"]["predicted_riskier_side"]
                )
                if "training_prompt" in group
                else None,
                "training_prompt_gold": str(
                    group["training_prompt"]["gold_riskier_side"]
                )
                if "training_prompt" in group
                else None,
                "training_prompt_side_swap_prediction": str(
                    group["training_prompt_side_swap"][
                        "predicted_riskier_side"
                    ]
                )
                if "training_prompt_side_swap" in group
                else None,
                "training_prompt_side_swap_gold": str(
                    group["training_prompt_side_swap"]["gold_riskier_side"]
                )
                if "training_prompt_side_swap" in group
                else None,
                "training_contract_swap_relation": (
                    group["training_prompt_side_swap"][
                        "predicted_riskier_side"
                    ]
                    != group["training_prompt"]["predicted_riskier_side"]
                )
                if "training_prompt_side_swap" in group
                else None,
                "post_diff_relation": (
                    group["padding_post_diff"]["predicted_riskier_side"]
                    == canonical_prediction
                ),
                "terminal_phrase_relation": (
                    group["padding_post_diff_terminal_phrase"][
                        "predicted_riskier_side"
                    ]
                    == canonical_prediction
                ),
                "all_visible": all_visible,
                "robust_success": success,
            }
        )

    post = variants["padding_post_diff"]
    terminal = variants["padding_post_diff_terminal_phrase"]
    canonical_swap = _swap_diagnostics(
        pair_records,
        base_prediction_key="canonical_prediction",
        base_gold_key="canonical_gold",
        swap_prediction_key="side_swap_prediction",
        swap_gold_key="side_swap_gold",
    )
    training_contract_swap = _swap_diagnostics(
        pair_records,
        base_prediction_key="training_prompt_prediction",
        base_gold_key="training_prompt_gold",
        swap_prediction_key="training_prompt_side_swap_prediction",
        swap_gold_key="training_prompt_side_swap_gold",
    )
    return {
        "metadata": model_metadata,
        "rows": len(rows),
        "pairs": complete,
        "canonical_accuracy": variants["canonical"]["accuracy"],
        "side_swap_equivariance": variants["side_swap"]["relation_accuracy"],
        "side_swap_independence_baseline": canonical_swap[
            "marginal_conditioned_independence_baseline"
        ],
        "side_swap_minus_independence_baseline": canonical_swap[
            "observed_minus_baseline"
        ],
        "side_swap_both_directions_correct": canonical_swap[
            "both_directions_correct"
        ],
        "training_contract_swap_equivariance": _boolean_mean(
            row["training_contract_swap_relation"] for row in pair_records
        ),
        "training_contract_swap_independence_baseline": training_contract_swap[
            "marginal_conditioned_independence_baseline"
        ],
        "training_contract_swap_minus_independence_baseline": training_contract_swap[
            "observed_minus_baseline"
        ],
        "training_contract_swap_both_directions_correct": training_contract_swap[
            "both_directions_correct"
        ],
        "metadata_removed_relation": variants["canonical_no_metadata"][
            "relation_accuracy"
        ],
        "pre_diff_relation": variants["padding_pre_diff"][
            "relation_accuracy"
        ],
        "post_diff_relation": post["relation_accuracy"],
        "terminal_phrase_relation": terminal["relation_accuracy"],
        "post_diff_a_to_b": post["a_to_b"],
        "post_diff_b_to_a": post["b_to_a"],
        "clean_post_diff_relation": post["clean_subset"]["relation_accuracy"],
        "robust_accuracy": robust / complete if complete else None,
        "clean_pair_coverage": clean_pairs / complete if complete else None,
        "clean_robust_accuracy_conditional": (
            clean_and_robust / clean_pairs if clean_pairs else None
        ),
        "clean_and_robust_coverage": (
            clean_and_robust / complete if complete else None
        ),
        "canonical_critical_hunk_truncated": variants["canonical"][
            "critical_hunk_truncated"
        ],
        "pair_records": pair_records,
    }


def compare_paired_models(
    qwen_records: list[dict[str, Any]],
    codebert_records: list[dict[str, Any]],
    *,
    iterations: int = 2000,
    seed: int = 42,
) -> dict[str, Any]:
    qwen = {
        (row["dataset"], row["pair_key"]): row for row in qwen_records
    }
    codebert = {
        (row["dataset"], row["pair_key"]): row
        for row in codebert_records
    }
    if qwen.keys() != codebert.keys():
        raise ValueError("paired model records must use identical pair keys")
    paired = [
        {"qwen": qwen[key], "codebert": codebert[key]}
        for key in sorted(qwen)
    ]
    subsets = {
        "all_pairs": paired,
        "jointly_clean": [
            row
            for row in paired
            if row["qwen"]["all_visible"]
            and row["codebert"]["all_visible"]
        ],
        "both_canonical_correct": [
            row
            for row in paired
            if row["qwen"]["canonical_correct"]
            and row["codebert"]["canonical_correct"]
        ],
        "canonical_confidence_gap_le_0_05": [
            row
            for row in paired
            if abs(
                row["qwen"]["canonical_confidence"]
                - row["codebert"]["canonical_confidence"]
            )
            <= 0.05
        ],
    }
    return {
        "bootstrap_iterations": iterations,
        "bootstrap_seed": seed,
        "subsets": {
            name: _paired_subset_summary(
                rows,
                iterations=iterations,
                seed=seed + index * 101,
            )
            for index, (name, rows) in enumerate(subsets.items())
        },
        "by_dataset": {
            dataset: _paired_subset_summary(
                [
                    row
                    for row in paired
                    if row["qwen"]["dataset"] == dataset
                ],
                iterations=iterations,
                seed=seed + 1000 + index * 101,
            )
            for index, dataset in enumerate(
                sorted({row["qwen"]["dataset"] for row in paired})
            )
        },
    }


def _paired_subset_summary(
    rows: list[dict[str, Any]],
    *,
    iterations: int,
    seed: int,
) -> dict[str, Any]:
    if not rows:
        return {"pairs": 0}

    def metrics(sample):
        endpoint = mean(
            int(row["codebert"]["post_diff_relation"])
            - int(row["qwen"]["post_diff_relation"])
            for row in sample
        )
        interaction = mean(
            (
                int(row["qwen"]["terminal_phrase_relation"])
                - int(row["qwen"]["post_diff_relation"])
            )
            - (
                int(row["codebert"]["terminal_phrase_relation"])
                - int(row["codebert"]["post_diff_relation"])
            )
            for row in sample
        )
        return endpoint, interaction

    endpoint, interaction = metrics(rows)
    rng = random.Random(seed)
    endpoint_samples = []
    interaction_samples = []
    for _ in range(iterations):
        sample = [rows[rng.randrange(len(rows))] for _ in rows]
        sample_endpoint, sample_interaction = metrics(sample)
        endpoint_samples.append(sample_endpoint)
        interaction_samples.append(sample_interaction)
    return {
        "pairs": len(rows),
        "qwen_post_diff_relation": _boolean_mean(
            row["qwen"]["post_diff_relation"] for row in rows
        ),
        "codebert_post_diff_relation": _boolean_mean(
            row["codebert"]["post_diff_relation"] for row in rows
        ),
        "qwen_training_contract_swap": _boolean_mean(
            row["qwen"]["training_contract_swap_relation"] for row in rows
        ),
        "codebert_training_contract_swap": _boolean_mean(
            row["codebert"]["training_contract_swap_relation"] for row in rows
        ),
        "endpoint_gap_codebert_minus_qwen": {
            "estimate": endpoint,
            "ci95": _percentile_interval(endpoint_samples),
        },
        "terminal_recovery_interaction": {
            "estimate": interaction,
            "ci95": _percentile_interval(interaction_samples),
        },
    }


def _boolean_mean(values) -> float:
    values = list(values)
    return sum(bool(value) for value in values) / len(values)


def _swap_diagnostics(
    rows: list[dict[str, Any]],
    *,
    base_prediction_key: str,
    base_gold_key: str,
    swap_prediction_key: str,
    swap_gold_key: str,
) -> dict[str, float]:
    complete = [
        row
        for row in rows
        if all(
            row.get(key) is not None
            for key in (
                base_prediction_key,
                base_gold_key,
                swap_prediction_key,
                swap_gold_key,
            )
        )
    ]
    if not complete:
        return {
            "observed_equivariance": 0.0,
            "marginal_conditioned_independence_baseline": 0.0,
            "observed_minus_baseline": 0.0,
            "both_directions_correct": 0.0,
        }
    base_b = _boolean_mean(
        row[base_prediction_key] == "B" for row in complete
    )
    swap_b = _boolean_mean(
        row[swap_prediction_key] == "B" for row in complete
    )
    observed = _boolean_mean(
        row[base_prediction_key] != row[swap_prediction_key]
        for row in complete
    )
    baseline = base_b * (1.0 - swap_b) + (1.0 - base_b) * swap_b
    both_correct = _boolean_mean(
        row[base_prediction_key] == row[base_gold_key]
        and row[swap_prediction_key] == row[swap_gold_key]
        for row in complete
    )
    return {
        "observed_equivariance": observed,
        "marginal_conditioned_independence_baseline": baseline,
        "observed_minus_baseline": observed - baseline,
        "both_directions_correct": both_correct,
    }


def _percentile_interval(values: list[float]) -> list[float]:
    ordered = sorted(values)
    low = ordered[int(0.025 * (len(ordered) - 1))]
    high = ordered[int(0.975 * (len(ordered) - 1))]
    return [low, high]

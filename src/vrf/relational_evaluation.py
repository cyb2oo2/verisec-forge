from __future__ import annotations

import math
import random
from collections import Counter, defaultdict
from typing import Any


VALID_LABELS = {"A", "B", "INSUFFICIENT_CONTEXT"}
FORCED_LABELS = {"A", "B"}


def normalize_label(value: Any) -> str:
    label = str(value or "").strip().upper()
    aliases = {
        "A_RISKIER": "A",
        "B_RISKIER": "B",
        "A": "A",
        "B": "B",
        "INSUFFICIENT": "INSUFFICIENT_CONTEXT",
        "INSUFFICIENT_CONTEXT": "INSUFFICIENT_CONTEXT",
    }
    normalized = aliases.get(label, label)
    return normalized if normalized in VALID_LABELS else "INVALID"


def protocol_valid(label: str) -> bool:
    return label in VALID_LABELS


def swap_label(label: str) -> str:
    if label == "A":
        return "B"
    if label == "B":
        return "A"
    return label


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _mean(rows: list[dict[str, Any]], field: str) -> float | None:
    values = [float(row[field]) for row in rows if row.get(field) is not None]
    return sum(values) / len(values) if values else None


def relation_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    valid_rows = [
        row
        for row in rows
        if row["base_protocol_valid"] and row["transformed_protocol_valid"]
    ]
    return {
        "transformed_accuracy": _mean(rows, "transformed_correct"),
        "base_protocol_pass_rate": _mean(rows, "base_protocol_valid"),
        "transformed_protocol_pass_rate": _mean(
            rows, "transformed_protocol_valid"
        ),
        "end_to_end_relation_accuracy": _mean(rows, "relation_success"),
        "relation_accuracy_conditional_valid": _mean(
            valid_rows, "relation_success"
        ),
        "relation_violation_rate": (
            1.0 - _mean(rows, "relation_success") if rows else None
        ),
        "robust_accuracy": _mean(rows, "robust_correct"),
        "mean_probability_relation_error": _mean(
            rows, "probability_relation_error"
        ),
    }


def context_pressure_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    forced_rows = [
        row for row in rows if row["transformed_prediction"] in FORCED_LABELS
    ]
    visible_rows = [
        row for row in rows if not row["critical_hunk_truncated"]
    ]
    truncated_rows = [
        row for row in rows if row["critical_hunk_truncated"]
    ]
    return {
        "decision_change_rate": _mean(rows, "decision_changed"),
        "abstention_rate": _mean(rows, "transformed_abstained"),
        "base_protocol_pass_rate": _mean(rows, "base_protocol_valid"),
        "transformed_protocol_pass_rate": _mean(
            rows, "transformed_protocol_valid"
        ),
        "mean_confidence_drop": _mean(rows, "confidence_drop"),
        "forced_decision_error_rate": (
            1.0 - _mean(forced_rows, "transformed_correct")
            if forced_rows
            else None
        ),
        "evidence_visible_rows": len(visible_rows),
        "evidence_truncated_rows": len(truncated_rows),
        "visible_decision_change_rate": _mean(
            visible_rows, "decision_changed"
        ),
        "truncated_decision_change_rate": _mean(
            truncated_rows, "decision_changed"
        ),
        "visible_abstention_rate": _mean(
            visible_rows, "transformed_abstained"
        ),
        "truncated_abstention_rate": _mean(
            truncated_rows, "transformed_abstained"
        ),
    }


def pair_cluster_bootstrap(
    rows: list[dict[str, Any]],
    *,
    metric: str,
    iterations: int,
    seed: int,
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        cluster_id = str(
            row.get("cluster_id")
            or f"{row.get('dataset', 'unknown')}::{row['pair_key']}"
        )
        grouped[cluster_id].append(row)
    keys = sorted(grouped)
    observed = relation_metrics(rows)[metric]
    if not keys or iterations <= 0:
        return {
            "observed": observed,
            "ci95_low": None,
            "ci95_high": None,
            "iterations": iterations,
            "pair_groups": len(keys),
            "cluster_key": "dataset::pair_key",
        }
    rng = random.Random(seed)
    samples = []
    for _ in range(iterations):
        sampled_rows = []
        for key in rng.choices(keys, k=len(keys)):
            sampled_rows.extend(grouped[key])
        samples.append(relation_metrics(sampled_rows)[metric])
    return {
        "observed": observed,
        "ci95_low": percentile(samples, 0.025),
        "ci95_high": percentile(samples, 0.975),
        "iterations": iterations,
        "pair_groups": len(keys),
        "cluster_key": "dataset::pair_key",
    }


def join_predictions(
    benchmark_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    predictions = {str(row["id"]): row for row in prediction_rows}
    missing = [
        str(row["id"])
        for row in benchmark_rows
        if str(row["id"]) not in predictions
    ]
    if missing:
        raise ValueError(
            f"missing predictions for {len(missing)} rows; first={missing[0]}"
        )
    joined = []
    for benchmark in benchmark_rows:
        prediction = predictions[str(benchmark["id"])]
        runtime = prediction.get("runtime_accounting") or benchmark.get(
            "runtime_accounting"
        )
        if runtime is None:
            raise ValueError(
                f"missing model-specific runtime accounting for {benchmark['id']}"
            )
        joined.append(
            {
                **benchmark,
                "predicted_riskier_side": normalize_label(
                    prediction.get(
                        "predicted_riskier_side",
                        prediction.get("prediction"),
                    )
                ),
                "probability_a": prediction.get("probability_a"),
                "confidence": prediction.get("confidence"),
                "runtime_accounting": runtime,
            }
        )
    return joined


def _confidence(row: dict[str, Any]) -> float | None:
    if row.get("confidence") is not None:
        return float(row["confidence"])
    if row.get("probability_a") is None:
        return None
    probability_a = float(row["probability_a"])
    return max(probability_a, 1.0 - probability_a)


def _scope_summary(
    base_rows: list[dict[str, Any]],
    interventions: list[dict[str, Any]],
    *,
    bootstrap_iterations: int,
    bootstrap_seed: int,
) -> dict[str, Any]:
    relation_rows = [
        row
        for row in interventions
        if row["expected_relation"] in {"invariant", "equivariant_swap"}
    ]
    invariant_rows = [
        row for row in relation_rows if row["expected_relation"] == "invariant"
    ]
    equivariant_rows = [
        row
        for row in relation_rows
        if row["expected_relation"] == "equivariant_swap"
    ]
    context_rows = [
        row
        for row in interventions
        if row["expected_relation"] == "context_pressure"
    ]
    base_visible_rows = [
        row for row in relation_rows if not row["base_critical_hunk_truncated"]
    ]
    clean_rows = [
        row
        for row in relation_rows
        if not row["base_critical_hunk_truncated"]
        and not row["critical_hunk_truncated"]
    ]
    templates = {}
    for template in sorted(
        {row["transformation_template"] for row in interventions}
    ):
        template_rows = [
            row
            for row in interventions
            if row["transformation_template"] == template
        ]
        if template_rows[0]["expected_relation"] == "context_pressure":
            metrics = context_pressure_metrics(template_rows)
        else:
            metrics = relation_metrics(template_rows)
        templates[template] = {
            "rows": len(template_rows),
            **metrics,
            "unexpected_a_to_b": sum(
                row["base_prediction"] == "A"
                and row["transformed_prediction"] == "B"
                and not row["relation_success"]
                for row in template_rows
            ),
            "unexpected_b_to_a": sum(
                row["base_prediction"] == "B"
                and row["transformed_prediction"] == "A"
                and not row["relation_success"]
                for row in template_rows
            ),
        }
    bootstrap = {}
    for metric_index, metric in enumerate(
        (
            "transformed_accuracy",
            "end_to_end_relation_accuracy",
            "robust_accuracy",
        )
    ):
        bootstrap[metric] = pair_cluster_bootstrap(
            relation_rows,
            metric=metric,
            iterations=bootstrap_iterations,
            seed=bootstrap_seed + metric_index,
        )
    base_accuracy = (
        sum(
            protocol_valid(normalize_label(row["predicted_riskier_side"]))
            and normalize_label(row["predicted_riskier_side"])
            == normalize_label(row["gold_riskier_side"])
            for row in base_rows
        )
        / len(base_rows)
        if base_rows
        else None
    )
    return {
        "base_rows": len(base_rows),
        "intervention_rows": len(interventions),
        "pair_groups": len(
            {
                row.get(
                    "cluster_id",
                    f"{row['dataset']}::{row['pair_key']}",
                )
                for row in interventions
            }
        ),
        "base_accuracy": base_accuracy,
        "base_protocol_pass_rate": (
            sum(
                protocol_valid(
                    normalize_label(row["predicted_riskier_side"])
                )
                for row in base_rows
            )
            / len(base_rows)
            if base_rows
            else None
        ),
        "relation_tests": relation_metrics(relation_rows),
        "invariant_only": {
            "rows": len(invariant_rows),
            **relation_metrics(invariant_rows),
        },
        "equivariant_only": {
            "rows": len(equivariant_rows),
            **relation_metrics(equivariant_rows),
        },
        "base_critical_visible": {
            "rows": len(base_visible_rows),
            **relation_metrics(base_visible_rows),
        },
        "clean_no_truncation": {
            "rows": len(clean_rows),
            **relation_metrics(clean_rows),
        },
        "context_pressure_only": {
            "rows": len(context_rows),
            **context_pressure_metrics(context_rows),
        },
        "transformation_introduced_truncation_rows": sum(
            row["transformation_introduced_critical_truncation"]
            for row in interventions
        ),
        "prediction_counts": dict(
            Counter(row["transformed_prediction"] for row in interventions)
        ),
        "by_template": templates,
        "pair_cluster_bootstrap": bootstrap,
    }


def _source_macro(dataset_summaries: dict[str, dict[str, Any]]) -> dict[str, Any]:
    metrics = (
        "transformed_accuracy",
        "end_to_end_relation_accuracy",
        "robust_accuracy",
    )
    output = {}
    for metric in metrics:
        values = [
            summary["relation_tests"][metric]
            for summary in dataset_summaries.values()
            if summary["relation_tests"][metric] is not None
        ]
        output[metric] = sum(values) / len(values) if values else None
    output["datasets"] = len(dataset_summaries)
    output["weighting"] = "equal_weight_per_dataset"
    return output


def evaluate_relational_predictions(
    rows: list[dict[str, Any]],
    *,
    bootstrap_iterations: int = 2000,
    bootstrap_seed: int = 42,
) -> dict[str, Any]:
    invalid_offset_rows = [
        str(row["id"])
        for row in rows
        if (row.get("runtime_accounting") or {}).get(
            "offset_mapping_quality"
        )
        != "exact_fast_tokenizer"
    ]
    if invalid_offset_rows:
        raise ValueError(
            "exact_fast_tokenizer runtime accounting is required; "
            f"first={invalid_offset_rows[0]}"
        )
    base_rows = {
        str(row["base_id"]): row
        for row in rows
        if row["expected_relation"] == "identity"
    }
    interventions = []
    for row in rows:
        relation = str(row["expected_relation"])
        if relation == "identity":
            continue
        base = base_rows.get(str(row["base_id"]))
        if base is None:
            raise ValueError(f"missing base row for {row['id']}")
        base_prediction = normalize_label(base["predicted_riskier_side"])
        transformed_prediction = normalize_label(row["predicted_riskier_side"])
        base_valid = protocol_valid(base_prediction)
        transformed_valid = protocol_valid(transformed_prediction)
        expected_prediction = (
            swap_label(base_prediction)
            if relation == "equivariant_swap"
            else base_prediction
        )
        relation_success = (
            relation != "context_pressure"
            and base_valid
            and transformed_valid
            and transformed_prediction == expected_prediction
        )
        base_correct = (
            base_valid
            and base_prediction == normalize_label(base["gold_riskier_side"])
        )
        transformed_correct = (
            transformed_valid
            and transformed_prediction
            == normalize_label(row["gold_riskier_side"])
        )
        base_probability = base.get("probability_a")
        transformed_probability = row.get("probability_a")
        probability_error = None
        if (
            relation != "context_pressure"
            and base_probability is not None
            and transformed_probability is not None
        ):
            expected_probability = (
                1.0 - float(base_probability)
                if relation == "equivariant_swap"
                else float(base_probability)
            )
            probability_error = abs(
                float(transformed_probability) - expected_probability
            )
        base_confidence = _confidence(base)
        transformed_confidence = _confidence(row)
        accounting = row.get("runtime_accounting") or {}
        interventions.append(
            {
                "id": row["id"],
                "base_id": row["base_id"],
                "pair_key": row["pair_key"],
                "cluster_id": row.get(
                    "cluster_id",
                    f"{row['dataset']}::{row['pair_key']}",
                ),
                "dataset": row["dataset"],
                "sampling_suite": row.get("sampling_suite"),
                "transformation_family": row["transformation_family"],
                "transformation_template": row["transformation_template"],
                "expected_relation": relation,
                "base_prediction": base_prediction,
                "transformed_prediction": transformed_prediction,
                "base_protocol_valid": base_valid,
                "transformed_protocol_valid": transformed_valid,
                "base_correct": base_correct,
                "transformed_correct": transformed_correct,
                "relation_success": relation_success,
                "robust_correct": (
                    relation != "context_pressure"
                    and base_correct
                    and transformed_correct
                    and relation_success
                ),
                "probability_relation_error": probability_error,
                "decision_changed": (
                    base_valid
                    and transformed_valid
                    and base_prediction != transformed_prediction
                ),
                "transformed_abstained": (
                    transformed_prediction == "INSUFFICIENT_CONTEXT"
                ),
                "confidence_drop": (
                    base_confidence - transformed_confidence
                    if base_confidence is not None
                    and transformed_confidence is not None
                    else None
                ),
                "critical_hunk_truncated": bool(
                    accounting.get("critical_hunk_truncated")
                ),
                "base_critical_hunk_truncated": bool(
                    accounting.get("base_critical_hunk_truncated")
                ),
                "transformation_introduced_critical_truncation": bool(
                    accounting.get(
                        "transformation_introduced_critical_truncation"
                    )
                ),
            }
        )

    suites = sorted(
        {
            str(row.get("sampling_suite") or "unspecified")
            for row in base_rows.values()
        }
    )
    datasets = sorted({str(row["dataset"]) for row in base_rows.values()})
    by_sampling_suite = {}
    by_sampling_suite_and_dataset = {}
    for suite_index, suite in enumerate(suites):
        suite_bases = [
            row
            for row in base_rows.values()
            if str(row.get("sampling_suite") or "unspecified") == suite
        ]
        suite_interventions = [
            row
            for row in interventions
            if str(row.get("sampling_suite") or "unspecified") == suite
        ]
        by_sampling_suite[suite] = _scope_summary(
            suite_bases,
            suite_interventions,
            bootstrap_iterations=bootstrap_iterations,
            bootstrap_seed=bootstrap_seed + suite_index * 100,
        )
        dataset_summaries = {}
        for dataset_index, dataset in enumerate(datasets):
            dataset_bases = [
                row for row in suite_bases if row["dataset"] == dataset
            ]
            dataset_interventions = [
                row
                for row in suite_interventions
                if row["dataset"] == dataset
            ]
            if not dataset_bases:
                continue
            dataset_summaries[dataset] = _scope_summary(
                dataset_bases,
                dataset_interventions,
                bootstrap_iterations=bootstrap_iterations,
                bootstrap_seed=(
                    bootstrap_seed
                    + suite_index * 100
                    + dataset_index * 10
                ),
            )
        by_sampling_suite_and_dataset[suite] = dataset_summaries
        by_sampling_suite[suite]["source_macro"] = _source_macro(
            dataset_summaries
        )
    by_dataset = {
        dataset: {
            suite: by_sampling_suite_and_dataset[suite][dataset]
            for suite in suites
            if dataset in by_sampling_suite_and_dataset[suite]
        }
        for dataset in datasets
    }
    representative_key = (
        "representative" if "representative" in by_sampling_suite else None
    )
    stress_key = (
        "balanced_stress" if "balanced_stress" in by_sampling_suite else None
    )
    return {
        "status": "ok",
        "base_rows": len(base_rows),
        "intervention_rows": len(interventions),
        "pair_groups": len(
            {
                row.get(
                    "cluster_id",
                    f"{row['dataset']}::{row['pair_key']}",
                )
                for row in interventions
            }
        ),
        "cluster_key": "dataset::pair_key",
        "headline_suite": representative_key,
        "stress_suite": stress_key,
        "headline": (
            by_sampling_suite[representative_key]
            if representative_key is not None
            else None
        ),
        "stress": (
            by_sampling_suite[stress_key]
            if stress_key is not None
            else None
        ),
        "by_sampling_suite": by_sampling_suite,
        "by_dataset": by_dataset,
        "by_sampling_suite_and_dataset": by_sampling_suite_and_dataset,
        "aggregate_metrics_omitted": True,
        "claim_boundary": (
            "The source-macro-balanced representative suite is the primary result; "
            "balanced-stress is reported independently. Overlapping pairs across suites "
            "are never mixed into a headline point estimate. Only invariant and "
            "equivariant transformations contribute to robust accuracy."
        ),
    }

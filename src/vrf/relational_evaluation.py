from __future__ import annotations

import math
import random
from collections import Counter, defaultdict
from typing import Any, Callable


VALID_LABELS = {"A", "B", "INSUFFICIENT_CONTEXT"}


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


def swap_label(label: str) -> str:
    if label == "A":
        return "B"
    if label == "B":
        return "A"
    return label


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _mean(rows: list[dict[str, Any]], field: str) -> float:
    return sum(float(row[field]) for row in rows) / len(rows) if rows else math.nan


def _metrics(rows: list[dict[str, Any]]) -> dict[str, float]:
    return {
        "transformed_accuracy": _mean(rows, "transformed_correct"),
        "relation_violation_rate": _mean(rows, "relation_violation"),
        "robust_accuracy": _mean(rows, "robust_correct"),
        "mean_probability_relation_error": _mean(
            [row for row in rows if row["probability_relation_error"] is not None],
            "probability_relation_error",
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
        grouped[str(row["pair_key"])].append(row)
    keys = sorted(grouped)
    observed = _metrics(rows)[metric]
    if not keys or iterations <= 0:
        return {
            "observed": observed,
            "ci95_low": math.nan,
            "ci95_high": math.nan,
            "iterations": iterations,
            "pair_groups": len(keys),
        }
    rng = random.Random(seed)
    samples = []
    for _ in range(iterations):
        sampled_rows = []
        for key in rng.choices(keys, k=len(keys)):
            sampled_rows.extend(grouped[key])
        samples.append(_metrics(sampled_rows)[metric])
    return {
        "observed": observed,
        "ci95_low": percentile(samples, 0.025),
        "ci95_high": percentile(samples, 0.975),
        "iterations": iterations,
        "pair_groups": len(keys),
    }


def join_predictions(
    benchmark_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    predictions = {str(row["id"]): row for row in prediction_rows}
    missing = [str(row["id"]) for row in benchmark_rows if str(row["id"]) not in predictions]
    if missing:
        raise ValueError(f"missing predictions for {len(missing)} rows; first={missing[0]}")
    joined = []
    for benchmark in benchmark_rows:
        prediction = predictions[str(benchmark["id"])]
        joined.append(
            {
                **benchmark,
                "predicted_riskier_side": normalize_label(
                    prediction.get("predicted_riskier_side", prediction.get("prediction"))
                ),
                "probability_a": prediction.get("probability_a"),
            }
        )
    return joined


def evaluate_relational_predictions(
    rows: list[dict[str, Any]],
    *,
    bootstrap_iterations: int = 2000,
    bootstrap_seed: int = 42,
) -> dict[str, Any]:
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
        expected_prediction = (
            swap_label(base_prediction)
            if relation == "equivariant_swap"
            else base_prediction
        )
        relation_success = transformed_prediction == expected_prediction
        base_correct = base_prediction == normalize_label(base["gold_riskier_side"])
        transformed_correct = transformed_prediction == normalize_label(row["gold_riskier_side"])
        base_probability = base.get("probability_a")
        transformed_probability = row.get("probability_a")
        probability_error = None
        if base_probability is not None and transformed_probability is not None:
            expected_probability = (
                1.0 - float(base_probability)
                if relation == "equivariant_swap"
                else float(base_probability)
            )
            probability_error = abs(float(transformed_probability) - expected_probability)
        accounting = row.get("token_accounting") or {}
        interventions.append(
            {
                "id": row["id"],
                "base_id": row["base_id"],
                "pair_key": row["pair_key"],
                "dataset": row["dataset"],
                "transformation_family": row["transformation_family"],
                "transformation_template": row["transformation_template"],
                "expected_relation": relation,
                "base_prediction": base_prediction,
                "transformed_prediction": transformed_prediction,
                "base_correct": base_correct,
                "transformed_correct": transformed_correct,
                "relation_violation": not relation_success,
                "robust_correct": base_correct and transformed_correct and relation_success,
                "probability_relation_error": probability_error,
                "critical_hunk_truncated": bool(accounting.get("critical_hunk_truncated")),
                "transformation_introduced_critical_truncation": bool(
                    accounting.get("transformation_introduced_critical_truncation")
                ),
            }
        )

    invariant_rows = [
        row for row in interventions if row["expected_relation"] == "invariant"
    ]
    context_rows = [
        row for row in interventions if row["expected_relation"] == "context_pressure"
    ]
    equivariant_rows = [
        row for row in interventions if row["expected_relation"] == "equivariant_swap"
    ]
    no_truncation_rows = [
        row for row in interventions if not row["critical_hunk_truncated"]
    ]
    templates = {}
    for template in sorted({row["transformation_template"] for row in interventions}):
        template_rows = [
            row for row in interventions if row["transformation_template"] == template
        ]
        templates[template] = {
            "rows": len(template_rows),
            **_metrics(template_rows),
            "unexpected_a_to_b": sum(
                row["base_prediction"] == "A"
                and row["transformed_prediction"] == "B"
                and row["relation_violation"]
                for row in template_rows
            ),
            "unexpected_b_to_a": sum(
                row["base_prediction"] == "B"
                and row["transformed_prediction"] == "A"
                and row["relation_violation"]
                for row in template_rows
            ),
        }

    bootstrap = {}
    for metric_index, metric in enumerate(
        ("transformed_accuracy", "relation_violation_rate", "robust_accuracy")
    ):
        bootstrap[metric] = pair_cluster_bootstrap(
            interventions,
            metric=metric,
            iterations=bootstrap_iterations,
            seed=bootstrap_seed + metric_index,
        )
    base_accuracy = (
        sum(
            normalize_label(row["predicted_riskier_side"])
            == normalize_label(row["gold_riskier_side"])
            for row in base_rows.values()
        )
        / len(base_rows)
        if base_rows
        else math.nan
    )
    return {
        "status": "ok",
        "base_rows": len(base_rows),
        "intervention_rows": len(interventions),
        "pair_groups": len({row["pair_key"] for row in interventions}),
        "base_accuracy": base_accuracy,
        "all_interventions": _metrics(interventions),
        "invariant_only": {"rows": len(invariant_rows), **_metrics(invariant_rows)},
        "equivariant_only": {"rows": len(equivariant_rows), **_metrics(equivariant_rows)},
        "context_pressure_only": {"rows": len(context_rows), **_metrics(context_rows)},
        "no_critical_hunk_truncation": {
            "rows": len(no_truncation_rows),
            **_metrics(no_truncation_rows),
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
        "claim_boundary": (
            "Invariant and equivariant transformations are scored as relation tests. "
            "Context-pressure rows are reported separately because truncation can change "
            "the information available to the model."
        ),
    }

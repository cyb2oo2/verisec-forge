from __future__ import annotations

from collections import Counter
from typing import Any

from vrf.relational_evaluation import (
    evaluate_relational_predictions,
    join_predictions,
    normalize_label,
)


ALLOWED_EXTERNAL_LABELS = {"A", "B", "A_RISKIER", "B_RISKIER", "INSUFFICIENT_CONTEXT"}


def build_prediction_template(
    benchmark_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "id": row["id"],
            "text": row["text"],
            "predicted_riskier_side": "",
            "probability_a": None,
            "supports_abstention": True,
        }
        for row in benchmark_rows
    ]


def validate_external_predictions(
    benchmark_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    benchmark_ids = [str(row["id"]) for row in benchmark_rows]
    benchmark_id_set = set(benchmark_ids)
    prediction_ids = [str(row.get("id", "")) for row in prediction_rows]
    counts = Counter(prediction_ids)
    duplicate_ids = sorted(row_id for row_id, count in counts.items() if count > 1)
    prediction_id_set = set(prediction_ids)
    missing_ids = sorted(benchmark_id_set - prediction_id_set)
    extra_ids = sorted(prediction_id_set - benchmark_id_set)
    invalid_labels = []
    normalized_counts: Counter[str] = Counter()
    for row in prediction_rows:
        label = str(row.get("predicted_riskier_side", row.get("prediction", ""))).strip()
        if label.upper() not in ALLOWED_EXTERNAL_LABELS:
            invalid_labels.append(
                {
                    "id": row.get("id"),
                    "predicted_riskier_side": label,
                }
            )
            continue
        normalized_counts[normalize_label(label)] += 1
    status = (
        "ok"
        if not duplicate_ids and not missing_ids and not extra_ids and not invalid_labels
        else "error"
    )
    return {
        "status": status,
        "benchmark_rows": len(benchmark_rows),
        "prediction_rows": len(prediction_rows),
        "duplicate_ids": duplicate_ids,
        "missing_ids": missing_ids,
        "extra_ids": extra_ids,
        "invalid_labels": invalid_labels,
        "prediction_distribution": dict(sorted(normalized_counts.items())),
        "allowed_labels": sorted(ALLOWED_EXTERNAL_LABELS),
    }


def evaluate_external_predictions(
    benchmark_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
    *,
    bootstrap_iterations: int = 2000,
    bootstrap_seed: int = 42,
) -> dict[str, Any]:
    validation = validate_external_predictions(benchmark_rows, prediction_rows)
    if validation["status"] != "ok":
        return {
            "status": "error",
            "validation": validation,
            "claim_boundary": external_claim_boundary(),
        }
    joined = join_predictions(benchmark_rows, prediction_rows)
    report = evaluate_relational_predictions(
        joined,
        bootstrap_iterations=bootstrap_iterations,
        bootstrap_seed=bootstrap_seed,
    )
    report["relational_claim_boundary"] = report.get("claim_boundary")
    report["external_adapter"] = {
        "status": "ok",
        "validation": validation,
        "prediction_contract": "one row per benchmark id with predicted_riskier_side in A/B/INSUFFICIENT_CONTEXT",
    }
    report["claim_boundary"] = external_claim_boundary()
    return report


def external_claim_boundary() -> str:
    return (
        "The external adapter evaluates supplied predictions against a fixed "
        "VeriPatch-RR benchmark artifact. It does not run a model, does not "
        "repair invalid outputs, and does not replace model-specific runtime "
        "materialization for full-scale claims."
    )

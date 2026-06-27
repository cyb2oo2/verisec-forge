from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from vrf.relational_evaluation import normalize_label, swap_label


SUPPORTED_RELATIONS = {"identity", "invariant", "equivariant_swap"}


def _probability_a(row: dict[str, Any]) -> float | None:
    value = row.get("probability_a")
    if value is None:
        return None
    probability = float(value)
    if probability < 0.0 or probability > 1.0:
        raise ValueError(f"probability_a must be in [0, 1], got {probability}")
    return probability


def _canonical_probability(row: dict[str, Any]) -> float | None:
    probability = _probability_a(row)
    if probability is None:
        return None
    relation = str(row.get("expected_relation"))
    if relation == "equivariant_swap":
        return 1.0 - probability
    if relation in {"identity", "invariant"}:
        return probability
    return None


def _project_probability(canonical_probability: float, relation: str) -> float:
    if relation == "equivariant_swap":
        return 1.0 - canonical_probability
    return canonical_probability


def _label_from_probability(probability_a: float) -> str:
    return "A" if probability_a >= 0.5 else "B"


def project_relation_consistent_predictions(
    benchmark_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Project probabilities within each paired relation group.

    This is a test-time structural operator. It uses only model probabilities
    and declared expected relations, never gold labels. Unsupported rows,
    missing probabilities, invalid labels, and context-pressure rows are carried
    through unchanged and counted in the audit summary.
    """

    predictions_by_id = {str(row["id"]): row for row in prediction_rows}
    missing = [
        str(row["id"])
        for row in benchmark_rows
        if str(row["id"]) not in predictions_by_id
    ]
    if missing:
        raise ValueError(f"missing predictions; first={missing[0]}")

    joined = []
    for benchmark in benchmark_rows:
        prediction = predictions_by_id[str(benchmark["id"])]
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
                "supports_abstention": prediction.get("supports_abstention"),
                "_prediction": prediction,
            }
        )

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in joined:
        grouped[str(row["base_id"])].append(row)

    output_by_id: dict[str, dict[str, Any]] = {}
    projection_rows = 0
    skipped_reasons: Counter[str] = Counter()
    probability_shifts: list[float] = []
    label_changes = 0

    for rows in grouped.values():
        canonical_values = [
            value
            for row in rows
            if str(row.get("expected_relation")) in SUPPORTED_RELATIONS
            for value in [_canonical_probability(row)]
            if value is not None
        ]
        can_project = len(canonical_values) == len(
            [
                row
                for row in rows
                if str(row.get("expected_relation")) in SUPPORTED_RELATIONS
            ]
        ) and bool(canonical_values)
        canonical_projection = (
            sum(canonical_values) / len(canonical_values)
            if can_project
            else None
        )

        for row in rows:
            prediction = dict(row["_prediction"])
            row_id = str(row["id"])
            relation = str(row.get("expected_relation"))
            original_label = normalize_label(
                prediction.get("predicted_riskier_side", prediction.get("prediction"))
            )

            if relation not in SUPPORTED_RELATIONS:
                skipped_reasons[f"unsupported_relation:{relation}"] += 1
                output_by_id[row_id] = prediction
                continue
            if original_label == "INVALID":
                skipped_reasons["invalid_label"] += 1
                output_by_id[row_id] = prediction
                continue
            if original_label == "INSUFFICIENT_CONTEXT":
                skipped_reasons["abstention"] += 1
                output_by_id[row_id] = prediction
                continue
            if canonical_projection is None:
                skipped_reasons["missing_probability"] += 1
                output_by_id[row_id] = prediction
                continue

            projected_probability = _project_probability(
                canonical_projection, relation
            )
            projected_label = _label_from_probability(projected_probability)
            if projected_label != original_label:
                label_changes += 1
            original_probability = _probability_a(row)
            if original_probability is not None:
                probability_shifts.append(
                    abs(projected_probability - original_probability)
                )
            prediction["predicted_riskier_side"] = projected_label
            prediction["probability_a"] = projected_probability
            prediction["relation_consistent_decoder"] = {
                "status": "projected",
                "expected_relation": relation,
                "canonical_probability_a": canonical_projection,
                "claim_boundary": (
                    "Test-time relation projection uses declared expected "
                    "relations and model probabilities only; it does not use "
                    "gold labels and must be evaluated against randomized-pair "
                    "controls before making performance claims."
                ),
            }
            projection_rows += 1
            output_by_id[row_id] = prediction

    projected = [output_by_id[str(row["id"])] for row in benchmark_rows]
    summary = {
        "status": "ok",
        "input_rows": len(benchmark_rows),
        "projected_rows": projection_rows,
        "skipped_rows": sum(skipped_reasons.values()),
        "skipped_reasons": dict(sorted(skipped_reasons.items())),
        "label_changes": label_changes,
        "mean_probability_shift": (
            sum(probability_shifts) / len(probability_shifts)
            if probability_shifts
            else None
        ),
        "claim_boundary": (
            "The relation-consistent decoder is a structural test-time "
            "projection operator. It is not a new model, not a benchmark "
            "result, and not evidence of improved reasoning without separate "
            "stress controls."
        ),
    }
    return {"predictions": projected, "summary": summary}

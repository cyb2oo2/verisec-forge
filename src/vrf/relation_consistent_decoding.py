from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from vrf.relational_evaluation import normalize_label, swap_label


RELATION_DECODER_INPUTS = {"identity", "invariant", "equivariant_swap"}
FORCED_LABELS = {"A", "B"}


def _base_id(row: dict[str, Any]) -> str:
    if str(row.get("expected_relation")) == "identity":
        return str(row["id"])
    return str(row.get("base_id") or row["id"])


def _prediction_index(prediction_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    predictions: dict[str, dict[str, Any]] = {}
    duplicates = []
    for row in prediction_rows:
        row_id = str(row["id"])
        if row_id in predictions:
            duplicates.append(row_id)
        predictions[row_id] = row
    if duplicates:
        raise ValueError(f"duplicate prediction ids; first={duplicates[0]}")
    return predictions


def _probability_a(prediction: dict[str, Any]) -> float | None:
    if prediction.get("probability_a") is not None:
        probability = float(prediction["probability_a"])
        if not 0.0 <= probability <= 1.0:
            raise ValueError(
                "probability_a must be in [0, 1]; "
                f"id={prediction.get('id')} probability_a={probability}"
            )
        return probability

    label = normalize_label(
        prediction.get("predicted_riskier_side", prediction.get("prediction"))
    )
    if label == "A":
        return 1.0
    if label == "B":
        return 0.0
    return None


def _canonical_probability(
    benchmark_row: dict[str, Any],
    prediction: dict[str, Any],
) -> float | None:
    probability = _probability_a(prediction)
    if probability is None:
        return None
    relation = str(benchmark_row["expected_relation"])
    if relation == "equivariant_swap":
        return 1.0 - probability
    if relation in {"identity", "invariant"}:
        return probability
    return None


def _output_probability(
    benchmark_row: dict[str, Any],
    canonical_probability_a: float,
) -> float:
    relation = str(benchmark_row["expected_relation"])
    if relation == "equivariant_swap":
        return 1.0 - canonical_probability_a
    return canonical_probability_a


def _label_from_probability(probability_a: float) -> str:
    return "A" if probability_a >= 0.5 else "B"


def relation_consistent_decode(
    benchmark_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
    *,
    minimum_candidates: int = 1,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Decode predictions through a canonical relation-consistent layer.

    The decoder projects identity, invariant, and side-swap predictions for a
    base example into one canonical probability that Side A is riskier. Side-swap
    rows contribute ``1 - probability_a`` because Side A in the swapped rendering
    corresponds to Side B in the canonical rendering.

    Output rows are then forced to preserve the declared relation:
    canonical/invariant rows receive the canonical decision, while side-swap rows
    receive the swapped decision. Context-pressure rows are preserved unchanged
    because their expected relation is intentionally not a clean invariance or
    equivariance contract.
    """

    if minimum_candidates < 1:
        raise ValueError("minimum_candidates must be at least 1")

    predictions = _prediction_index(prediction_rows)
    missing = [
        str(row["id"])
        for row in benchmark_rows
        if str(row["id"]) not in predictions
    ]
    if missing:
        raise ValueError(
            f"missing predictions for {len(missing)} rows; first={missing[0]}"
        )

    candidates: dict[str, list[float]] = defaultdict(list)
    candidate_relations: dict[str, Counter[str]] = defaultdict(Counter)
    skipped_candidates: Counter[str] = Counter()

    for row in benchmark_rows:
        relation = str(row["expected_relation"])
        if relation not in RELATION_DECODER_INPUTS:
            continue
        prediction = predictions[str(row["id"])]
        canonical_probability = _canonical_probability(row, prediction)
        if canonical_probability is None:
            skipped_candidates[relation] += 1
            continue
        key = _base_id(row)
        candidates[key].append(canonical_probability)
        candidate_relations[key][relation] += 1

    canonical_probabilities = {
        key: sum(values) / len(values)
        for key, values in candidates.items()
        if len(values) >= minimum_candidates
    }

    decoded_rows: list[dict[str, Any]] = []
    changed_predictions = 0
    decoded_relation_counts: Counter[str] = Counter()
    preserved_relation_counts: Counter[str] = Counter()

    for row in benchmark_rows:
        row_id = str(row["id"])
        prediction = dict(predictions[row_id])
        original_label = normalize_label(
            prediction.get("predicted_riskier_side", prediction.get("prediction"))
        )
        relation = str(row["expected_relation"])
        key = _base_id(row)
        canonical_probability = canonical_probabilities.get(key)

        if relation in RELATION_DECODER_INPUTS and canonical_probability is not None:
            output_probability = _output_probability(row, canonical_probability)
            output_label = _label_from_probability(output_probability)
            prediction["predicted_riskier_side"] = output_label
            prediction["probability_a"] = output_probability
            prediction["confidence"] = max(output_probability, 1.0 - output_probability)
            prediction["relation_consistent_decoder"] = {
                "method": "canonical_probability_projection",
                "base_id": key,
                "expected_relation": relation,
                "canonical_probability_a": canonical_probability,
                "candidate_count": len(candidates[key]),
                "candidate_relations": dict(sorted(candidate_relations[key].items())),
            }
            decoded_relation_counts[relation] += 1
            if original_label != output_label:
                changed_predictions += 1
        else:
            prediction.setdefault("relation_consistent_decoder", None)
            preserved_relation_counts[relation] += 1

        decoded_rows.append(prediction)

    report = {
        "status": "ok",
        "method": "relation_consistent_decoder",
        "input_rows": len(benchmark_rows),
        "decoded_rows": sum(decoded_relation_counts.values()),
        "preserved_rows": sum(preserved_relation_counts.values()),
        "base_groups_with_candidates": len(candidates),
        "base_groups_decoded": len(canonical_probabilities),
        "minimum_candidates": minimum_candidates,
        "changed_predictions": changed_predictions,
        "decoded_relation_counts": dict(sorted(decoded_relation_counts.items())),
        "preserved_relation_counts": dict(sorted(preserved_relation_counts.items())),
        "skipped_candidate_counts": dict(sorted(skipped_candidates.items())),
        "claim_boundary": (
            "This is a deterministic relation-consistent decoding layer over "
            "existing predictions. It can enforce declared invariant and "
            "side-swap contracts, but it is not learned side-order reasoning "
            "and does not create new model-quality evidence by itself."
        ),
    }
    return decoded_rows, report


def decoded_label_pair(base_label: str) -> tuple[str, str]:
    """Return the forced canonical/swap label pair for a canonical decision."""

    canonical = normalize_label(base_label)
    if canonical not in FORCED_LABELS:
        raise ValueError(f"expected forced A/B label, got {base_label!r}")
    return canonical, swap_label(canonical)

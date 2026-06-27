from __future__ import annotations

import random
from typing import Any

from vrf.external_adapter import evaluate_external_predictions
from vrf.relation_consistent_decoder import project_relation_consistent_predictions
from vrf.relational_evaluation import join_predictions


def shuffled_base_id_rows(
    benchmark_rows: list[dict[str, Any]],
    *,
    seed: int = 42,
) -> list[dict[str, Any]]:
    """Return benchmark rows with non-identity base ids shuffled.

    This keeps row IDs and predictions unchanged while breaking the declared
    pairing structure used by relation-consistent projection. It is a negative
    control for the decoder, not a new benchmark transformation.
    """

    base_ids = [
        str(row["id"])
        for row in benchmark_rows
        if str(row.get("expected_relation")) == "identity"
    ]
    if len(base_ids) < 2:
        return [dict(row) for row in benchmark_rows]

    rng = random.Random(seed)
    shuffled = base_ids[:]
    for _ in range(10):
        rng.shuffle(shuffled)
        if any(left != right for left, right in zip(base_ids, shuffled)):
            break
    mapping = dict(zip(base_ids, shuffled))
    if all(left == right for left, right in mapping.items()):
        shuffled = shuffled[1:] + shuffled[:1]
        mapping = dict(zip(base_ids, shuffled))

    output = []
    for row in benchmark_rows:
        copied = dict(row)
        relation = str(copied.get("expected_relation"))
        if relation != "identity":
            copied["base_id"] = mapping.get(str(copied["base_id"]), copied["base_id"])
        output.append(copied)
    return output


def _relation_metrics(report: dict[str, Any]) -> dict[str, Any]:
    relation_tests = report["headline"]["relation_tests"]
    return {
        "base_accuracy": report["headline"]["base_accuracy"],
        "relation_success": relation_tests["end_to_end_relation_accuracy"],
        "robust_accuracy": relation_tests["robust_accuracy"],
        "relation_violation_rate": relation_tests["relation_violation_rate"],
        "swap_consistency": report["headline"]["equivariant_only"][
            "end_to_end_relation_accuracy"
        ],
    }


def _identity_distortion_rate(
    benchmark_rows: list[dict[str, Any]],
    before_predictions: list[dict[str, Any]],
    after_predictions: list[dict[str, Any]],
) -> float | None:
    identity_ids = {
        str(row["id"])
        for row in benchmark_rows
        if str(row.get("expected_relation")) == "identity"
    }
    if not identity_ids:
        return None
    before = {str(row["id"]): row for row in before_predictions}
    after = {str(row["id"]): row for row in after_predictions}
    changed = 0
    for row_id in identity_ids:
        if before[row_id].get("predicted_riskier_side") != after[row_id].get(
            "predicted_riskier_side"
        ):
            changed += 1
    return changed / len(identity_ids)


def run_decoder_stress_validation(
    benchmark_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
    *,
    bootstrap_iterations: int = 2000,
    randomized_seed: int = 42,
) -> dict[str, Any]:
    baseline = evaluate_external_predictions(
        benchmark_rows,
        prediction_rows,
        bootstrap_iterations=bootstrap_iterations,
    )
    decoded = project_relation_consistent_predictions(
        benchmark_rows, prediction_rows
    )
    decoded_report = evaluate_external_predictions(
        benchmark_rows,
        decoded["predictions"],
        bootstrap_iterations=bootstrap_iterations,
    )

    randomized_rows = shuffled_base_id_rows(
        benchmark_rows, seed=randomized_seed
    )
    randomized_decoded = project_relation_consistent_predictions(
        randomized_rows, prediction_rows
    )
    randomized_report = evaluate_external_predictions(
        benchmark_rows,
        randomized_decoded["predictions"],
        bootstrap_iterations=bootstrap_iterations,
    )

    baseline_metrics = _relation_metrics(baseline)
    decoded_metrics = _relation_metrics(decoded_report)
    randomized_metrics = _relation_metrics(randomized_report)
    joined_baseline = join_predictions(benchmark_rows, prediction_rows)
    decoded_summary = decoded["summary"]
    randomized_summary = randomized_decoded["summary"]

    relation_success_delta = (
        decoded_metrics["relation_success"] - baseline_metrics["relation_success"]
    )
    swap_consistency_gain = (
        decoded_metrics["swap_consistency"] - baseline_metrics["swap_consistency"]
    )
    randomized_pair_control_gap = (
        decoded_metrics["relation_success"]
        - randomized_metrics["relation_success"]
    )

    return {
        "status": "ok",
        "baseline": baseline_metrics,
        "decoded": decoded_metrics,
        "randomized_pair_control": randomized_metrics,
        "decoder_summary": decoded_summary,
        "randomized_decoder_summary": randomized_summary,
        "stress_metrics": {
            "relation_success_delta": relation_success_delta,
            "swap_consistency_gain": swap_consistency_gain,
            "identity_distortion_rate": _identity_distortion_rate(
                benchmark_rows, joined_baseline, decoded["predictions"]
            ),
            "randomized_pair_control_gap": randomized_pair_control_gap,
            "projected_row_coverage": (
                decoded_summary["projected_rows"] / decoded_summary["input_rows"]
                if decoded_summary["input_rows"]
                else None
            ),
            "invalid_or_abstention_preservation": {
                "abstention_skips": decoded_summary["skipped_reasons"].get(
                    "abstention", 0
                ),
                "invalid_label_skips": decoded_summary["skipped_reasons"].get(
                    "invalid_label", 0
                ),
            },
        },
        "claim_boundary": (
            "This stress validation checks whether relation-consistent decoding "
            "behaves like structure projection rather than arbitrary metric "
            "reshaping. It is still a post-hoc control report, not a model "
            "quality claim or benchmark leaderboard."
        ),
    }

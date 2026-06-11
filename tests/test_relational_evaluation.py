import json

import pytest

from vrf.relational_evaluation import (
    evaluate_relational_predictions,
    join_predictions,
    pair_cluster_bootstrap,
)


def benchmark_row(
    row_id,
    *,
    base_id,
    relation,
    gold,
    prediction,
    probability_a,
    truncated=False,
    dataset="demo",
    pair_key="pair-1",
):
    return {
        "id": row_id,
        "base_id": base_id,
        "pair_key": pair_key,
        "cluster_id": f"{dataset}::{pair_key}",
        "dataset": dataset,
        "transformation_family": "base" if relation == "identity" else "test",
        "transformation_template": row_id,
        "expected_relation": relation,
        "gold_riskier_side": gold,
        "predicted_riskier_side": prediction,
        "probability_a": probability_a,
        "runtime_accounting": {
            "critical_hunk_truncated": truncated,
            "base_critical_hunk_truncated": False,
        },
    }


def test_relational_metrics_separate_relation_and_context_pressure():
    rows = [
        benchmark_row(
            "pair-1::base",
            base_id="pair-1::base",
            relation="identity",
            gold="A",
            prediction="A",
            probability_a=0.8,
        ),
        benchmark_row(
            "pair-1::metadata",
            base_id="pair-1::base",
            relation="invariant",
            gold="A",
            prediction="A",
            probability_a=0.7,
        ),
        benchmark_row(
            "pair-1::swap",
            base_id="pair-1::base",
            relation="equivariant_swap",
            gold="B",
            prediction="B",
            probability_a=0.2,
        ),
        benchmark_row(
            "pair-1::pressure",
            base_id="pair-1::base",
            relation="context_pressure",
            gold="A",
            prediction="INSUFFICIENT_CONTEXT",
            probability_a=None,
            truncated=True,
        ),
    ]
    report = evaluate_relational_predictions(
        rows, bootstrap_iterations=20, bootstrap_seed=7
    )

    assert report["relation_tests"]["robust_accuracy"] == 1.0
    assert report["context_pressure_only"]["abstention_rate"] == 1.0
    assert "robust_accuracy" not in report["context_pressure_only"]
    assert report["context_pressure_only"]["evidence_truncated_rows"] == 1
    json.dumps(report, allow_nan=False)


def test_invalid_to_invalid_never_counts_as_relation_success():
    rows = [
        benchmark_row(
            "base",
            base_id="base",
            relation="identity",
            gold="A",
            prediction="garbage",
            probability_a=None,
        ),
        benchmark_row(
            "invariant",
            base_id="base",
            relation="invariant",
            gold="A",
            prediction="garbage",
            probability_a=None,
        ),
    ]
    report = evaluate_relational_predictions(
        rows, bootstrap_iterations=0
    )

    assert report["base_protocol_pass_rate"] == 0.0
    assert (
        report["invariant_only"]["end_to_end_relation_accuracy"] == 0.0
    )


def test_join_predictions_requires_runtime_accounting():
    benchmark = [{"id": "a"}]
    with pytest.raises(ValueError, match="runtime accounting"):
        join_predictions(
            benchmark, [{"id": "a", "prediction": "A"}]
        )


def test_pair_cluster_bootstrap_scopes_pair_key_by_dataset():
    rows = []
    for dataset in ("one", "two"):
        rows.append(
            {
                "pair_key": "same",
                "dataset": dataset,
                "cluster_id": f"{dataset}::same",
                "transformed_correct": True,
                "base_protocol_valid": True,
                "transformed_protocol_valid": True,
                "relation_success": True,
                "robust_correct": True,
                "probability_relation_error": 0.1,
            }
        )
    report = pair_cluster_bootstrap(
        rows,
        metric="robust_accuracy",
        iterations=20,
        seed=9,
    )

    assert report["pair_groups"] == 2
    assert report["cluster_key"] == "dataset::pair_key"

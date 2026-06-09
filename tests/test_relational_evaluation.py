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
):
    return {
        "id": row_id,
        "base_id": base_id,
        "pair_key": base_id,
        "dataset": "demo",
        "transformation_family": "base" if relation == "identity" else "test",
        "transformation_template": row_id,
        "expected_relation": relation,
        "gold_riskier_side": gold,
        "predicted_riskier_side": prediction,
        "probability_a": probability_a,
        "token_accounting": {"critical_hunk_truncated": truncated},
    }


def test_relational_metrics_separate_invariance_swap_and_truncation():
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
            prediction="B",
            probability_a=0.3,
            truncated=True,
        ),
    ]
    report = evaluate_relational_predictions(
        rows, bootstrap_iterations=20, bootstrap_seed=7
    )

    assert report["base_accuracy"] == 1.0
    assert report["invariant_only"]["robust_accuracy"] == 1.0
    assert report["equivariant_only"]["relation_violation_rate"] == 0.0
    assert report["context_pressure_only"]["relation_violation_rate"] == 1.0
    assert report["no_critical_hunk_truncation"]["rows"] == 2


def test_join_predictions_requires_every_benchmark_id():
    benchmark = [{"id": "a"}, {"id": "b"}]
    with pytest.raises(ValueError, match="missing predictions"):
        join_predictions(benchmark, [{"id": "a", "prediction": "A"}])


def test_pair_cluster_bootstrap_reports_pair_count():
    rows = [
        {
            "pair_key": f"pair-{index // 2}",
            "transformed_correct": index % 2 == 0,
            "relation_violation": index % 3 == 0,
            "robust_correct": index % 2 == 0,
            "probability_relation_error": 0.1,
        }
        for index in range(8)
    ]
    report = pair_cluster_bootstrap(
        rows, metric="robust_accuracy", iterations=30, seed=9
    )

    assert report["pair_groups"] == 4
    assert report["ci95_low"] <= report["observed"] <= report["ci95_high"]

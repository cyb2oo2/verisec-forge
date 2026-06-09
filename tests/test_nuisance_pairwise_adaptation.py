from scripts.compare_nuisance_pairwise_adaptation import (
    exact_mcnemar,
    paired_orientation_comparison,
    paired_relation_comparison,
)


def test_exact_mcnemar_favors_one_sided_repairs() -> None:
    assert exact_mcnemar(10, 0) < 0.01
    assert exact_mcnemar(2, 2) == 1.0


def test_paired_orientation_comparison_counts_repairs() -> None:
    baseline = [
        {"pair_key": "a", "correct_orientation": False},
        {"pair_key": "b", "correct_orientation": True},
    ]
    adapted = [
        {"pair_key": "a", "correct_orientation": True},
        {"pair_key": "b", "correct_orientation": True},
    ]

    result = paired_orientation_comparison(baseline, adapted)

    assert result["repaired"] == 1
    assert result["introduced"] == 0
    assert result["accuracy_delta"] == 0.5


def test_paired_relation_comparison_uses_expected_relation() -> None:
    baseline = [
        {
            "id": "x",
            "intervention": "padding",
            "expected_relation": "invariant",
            "base_pred": 0,
            "intervention_pred": 1,
        }
    ]
    adapted = [
        {
            "id": "x",
            "intervention": "padding",
            "expected_relation": "invariant",
            "base_pred": 0,
            "intervention_pred": 0,
        }
    ]

    result = paired_relation_comparison(baseline, adapted)["padding"]

    assert result["repaired_violations"] == 1
    assert result["introduced_violations"] == 0

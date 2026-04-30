from __future__ import annotations

from scripts.analyze_primevul_router_statistics import (
    bootstrap_delta,
    exact_sign_test,
    group_metric_values,
)


def test_group_metric_values_computes_pair_orientation() -> None:
    rows = [
        {"pair_key": "a", "gold": 1, "pred": 1, "vuln_probability": 0.8},
        {"pair_key": "a", "gold": 0, "pred": 0, "vuln_probability": 0.2},
        {"pair_key": "b", "gold": 1, "pred": 0, "vuln_probability": 0.1},
    ]

    values = group_metric_values(rows)

    assert values["a"]["group_all_correct"] == 1
    assert values["a"]["orientation"] == 1
    assert values["b"]["group_all_correct"] == 0
    assert values["b"]["orientation_eligible"] == 0


def test_exact_sign_test_counts_wins_losses_and_ties() -> None:
    baseline = {
        "a": {"group_all_correct": 0, "orientation": 1, "orientation_eligible": 1},
        "b": {"group_all_correct": 1, "orientation": 0, "orientation_eligible": 1},
        "c": {"group_all_correct": 1, "orientation": 1, "orientation_eligible": 1},
    }
    router = {
        "a": {"group_all_correct": 1, "orientation": 1, "orientation_eligible": 1},
        "b": {"group_all_correct": 0, "orientation": 1, "orientation_eligible": 1},
        "c": {"group_all_correct": 1, "orientation": 1, "orientation_eligible": 1},
    }

    result = exact_sign_test(baseline, router, metric="group_all_correct")

    assert result["wins"] == 1
    assert result["losses"] == 1
    assert result["ties"] == 1
    assert result["two_sided_p_value"] == 1.0


def test_bootstrap_delta_reports_observed_mean_delta() -> None:
    baseline = {
        "a": {"group_all_correct": 0, "orientation": 1, "orientation_eligible": 1},
        "b": {"group_all_correct": 0, "orientation": 1, "orientation_eligible": 1},
    }
    router = {
        "a": {"group_all_correct": 1, "orientation": 1, "orientation_eligible": 1},
        "b": {"group_all_correct": 0, "orientation": 1, "orientation_eligible": 1},
    }

    result = bootstrap_delta(baseline, router, metric="group_all_correct", iterations=20, seed=1)

    assert result["observed_delta"] == 0.5
    assert result["units"] == 2

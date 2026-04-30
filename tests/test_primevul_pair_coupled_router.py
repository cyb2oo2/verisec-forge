from __future__ import annotations

from scripts.evaluate_primevul_pair_coupled_router import apply_pair_coupling, select_margin


def test_apply_pair_coupling_assigns_higher_probability_positive() -> None:
    rows = [
        {"id": "a", "pair_key": "p", "gold": 0, "pred": 0, "vuln_probability": 0.9},
        {"id": "b", "pair_key": "p", "gold": 1, "pred": 1, "vuln_probability": 0.1},
    ]

    coupled, counts = apply_pair_coupling(rows, margin=0.0)

    assert counts["coupled_groups"] == 1
    assert coupled[0]["pred"] == 1
    assert coupled[1]["pred"] == 0
    assert all(row["pair_coupled"] for row in coupled)


def test_apply_pair_coupling_respects_margin() -> None:
    rows = [
        {"id": "a", "pair_key": "p", "gold": 0, "pred": 0, "vuln_probability": 0.51},
        {"id": "b", "pair_key": "p", "gold": 1, "pred": 1, "vuln_probability": 0.49},
    ]

    coupled, counts = apply_pair_coupling(rows, margin=0.05)

    assert counts["coupled_groups"] == 0
    assert [row["pred"] for row in coupled] == [0, 1]


def test_apply_pair_coupling_does_not_use_gold_for_eligibility() -> None:
    rows = [
        {"id": "a", "pair_key": "p", "gold": 0, "pred": 0, "vuln_probability": 0.9},
        {"id": "b", "pair_key": "p", "gold": 0, "pred": 0, "vuln_probability": 0.1},
    ]

    coupled, counts = apply_pair_coupling(rows, margin=0.0)

    assert counts["coupled_groups"] == 1
    assert [row["pred"] for row in coupled] == [1, 0]


def test_select_margin_can_use_orientation_metric() -> None:
    rows = [
        {
            "margin": 0.0,
            "overall": {"balanced_accuracy": 0.8, "f1": 0.8},
            "group_metrics": {"orientation_accuracy": 0.9, "group_all_correct_rate": 0.7},
        },
        {
            "margin": 0.1,
            "overall": {"balanced_accuracy": 0.81, "f1": 0.8},
            "group_metrics": {"orientation_accuracy": 0.88, "group_all_correct_rate": 0.72},
        },
    ]

    assert select_margin(rows, selector="orientation_accuracy")["margin"] == 0.0
    assert select_margin(rows, selector="group_all_correct_rate")["margin"] == 0.1
    assert select_margin(rows, selector="balanced_accuracy")["selection_scores"]["tie_break"] == "lowest_margin"

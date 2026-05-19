from __future__ import annotations

from scripts.build_primevul_pair_coupled_significance_chart import render_svg


def test_pair_coupled_significance_chart_includes_deltas_and_caveat() -> None:
    payload = {
        "strict_pair_minus_bucket": {
            "balanced_accuracy_delta": {"mean": 0.0348, "ci95_low": 0.0329, "ci95_high": 0.0368},
            "group_all_correct_delta": {"mean": 0.1114, "ci95_low": 0.1046, "ci95_high": 0.1199},
            "positive_balanced_accuracy_splits": 5,
            "positive_group_all_correct_splits": 5,
            "total_splits": 5,
        },
        "headline_pair_minus_diff_only": {"balanced_accuracy_delta": 0.0285},
        "diff_only_three_seed": {"mean": 0.8287, "ci95_low": 0.8158, "ci95_high": 0.8382},
        "pair_coupled_multisplit": {"mean": 0.8572, "ci95_low": 0.8523, "ci95_high": 0.8616},
        "paired_tests": {
            "row_mcnemar_p_values": [0.001],
            "group_all_correct_sign_p_values": [0.001],
        },
    }

    svg = render_svg(payload)

    assert svg.startswith("<svg")
    assert "Pair-Coupled Decoding" in svg
    assert "+0.0348" in svg
    assert "Narrative comparison, not strict paired test" in svg

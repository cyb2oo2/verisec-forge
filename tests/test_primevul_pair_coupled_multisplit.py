from __future__ import annotations

from scripts.build_primevul_pair_coupled_significance_summary import build_summary as build_significance_summary
from scripts.build_primevul_pair_coupled_significance_summary import render_markdown as render_significance_markdown
from scripts.analyze_primevul_pair_coupled_multisplit import build_summary, mcnemar_exact


def test_mcnemar_exact_counts_discordant_rows() -> None:
    rows_a = [
        {"id": "a", "gold": 1, "pred": 1},
        {"id": "b", "gold": 1, "pred": 0},
        {"id": "c", "gold": 0, "pred": 0},
    ]
    rows_b = [
        {"id": "a", "gold": 1, "pred": 0},
        {"id": "b", "gold": 1, "pred": 1},
        {"id": "c", "gold": 0, "pred": 0},
    ]

    result = mcnemar_exact(rows_a, rows_b)

    assert result["a_correct_b_wrong"] == 1
    assert result["a_wrong_b_correct"] == 1
    assert result["both_correct"] == 1
    assert result["discordant"] == 2


def test_build_summary_reports_stability_fields() -> None:
    seed_reports = [
        {
            "baseline": {"overall": {"balanced_accuracy": 0.8}},
            "bucket_router": {
                "overall": {"balanced_accuracy": 0.81},
                "group_metrics": {"group_all_correct_rate": 0.7},
            },
            "pair_coupled": {
                "overall": {"balanced_accuracy": 0.85},
                "group_metrics": {"group_all_correct_rate": 0.8},
            },
            "deltas": {
                "pair_minus_bucket_balanced_accuracy": 0.04,
                "pair_minus_bucket_group_all_correct": 0.1,
            },
        },
        {
            "baseline": {"overall": {"balanced_accuracy": 0.82}},
            "bucket_router": {
                "overall": {"balanced_accuracy": 0.83},
                "group_metrics": {"group_all_correct_rate": 0.72},
            },
            "pair_coupled": {
                "overall": {"balanced_accuracy": 0.86},
                "group_metrics": {"group_all_correct_rate": 0.81},
            },
            "deltas": {
                "pair_minus_bucket_balanced_accuracy": 0.03,
                "pair_minus_bucket_group_all_correct": 0.09,
            },
        },
    ]

    summary = build_summary(seed_reports)

    assert summary["pair_minus_bucket_balanced_accuracy"]["mean"] == 0.035
    assert summary["pair_minus_bucket_group_all_correct"]["min"] == 0.09


def test_pair_coupled_significance_summary_separates_strict_and_headline_claims() -> None:
    payload = {
        "seeds": [
            {
                "bucket_router": {
                    "overall": {"balanced_accuracy": 0.8},
                    "group_metrics": {"group_all_correct_rate": 0.7},
                },
                "pair_coupled": {
                    "overall": {"balanced_accuracy": 0.85},
                    "group_metrics": {"group_all_correct_rate": 0.8},
                },
                "deltas": {
                    "pair_minus_bucket_balanced_accuracy": 0.05,
                    "pair_minus_bucket_group_all_correct": 0.1,
                },
                "tests": {
                    "pair_vs_bucket_row_mcnemar": {"two_sided_p_value": 0.01},
                    "pair_vs_bucket_group_all_correct_sign": {"two_sided_p_value": 0.02},
                    "pair_vs_bucket_orientation_sign": {"two_sided_p_value": 1.0},
                },
            },
            {
                "bucket_router": {
                    "overall": {"balanced_accuracy": 0.82},
                    "group_metrics": {"group_all_correct_rate": 0.72},
                },
                "pair_coupled": {
                    "overall": {"balanced_accuracy": 0.86},
                    "group_metrics": {"group_all_correct_rate": 0.81},
                },
                "deltas": {
                    "pair_minus_bucket_balanced_accuracy": 0.04,
                    "pair_minus_bucket_group_all_correct": 0.09,
                },
                "tests": {
                    "pair_vs_bucket_row_mcnemar": {"two_sided_p_value": 0.03},
                    "pair_vs_bucket_group_all_correct_sign": {"two_sided_p_value": 0.04},
                    "pair_vs_bucket_orientation_sign": {"two_sided_p_value": 1.0},
                },
            },
        ]
    }

    summary = build_significance_summary(payload, iterations=100, seed=1)
    markdown = render_significance_markdown(summary)

    assert summary["strict_pair_minus_bucket"]["positive_balanced_accuracy_splits"] == 2
    assert summary["strict_pair_minus_bucket"]["balanced_accuracy_delta"]["mean"] == 0.045
    assert "Strict Same-Split Claim" in markdown
    assert "Headline Comparison" in markdown
    assert "protocol caveat" in markdown

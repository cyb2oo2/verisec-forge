from __future__ import annotations

from scripts.analyze_primevul_pair_side_correction_multisplit import summarize


def test_multisplit_summary_tracks_positive_and_negative_deltas() -> None:
    rows = [
        {
            "eval": {
                "baseline": {"balanced_accuracy": 0.8, "group_all_correct_rate": 0.7},
                "corrected": {"balanced_accuracy": 0.81, "group_all_correct_rate": 0.69},
                "gated_groups": 2,
            }
        },
        {
            "eval": {
                "baseline": {"balanced_accuracy": 0.8, "group_all_correct_rate": 0.7},
                "corrected": {"balanced_accuracy": 0.79, "group_all_correct_rate": 0.72},
                "gated_groups": 4,
            }
        },
    ]

    summary = summarize(rows)

    assert summary["balanced_accuracy_delta"]["positive_splits"] == 1
    assert summary["balanced_accuracy_delta"]["negative_splits"] == 1
    assert summary["gated_groups"]["mean"] == 3.0

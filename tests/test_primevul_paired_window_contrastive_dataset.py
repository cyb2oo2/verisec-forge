from __future__ import annotations

from scripts.build_primevul_paired_window_contrastive_dataset import build_dataset


def test_build_dataset_orders_side_a_by_probability_and_labels_inversion() -> None:
    predictions = [
        {"id": "fixed", "pair_key": "p1", "gold": 0, "vuln_probability": 0.91, "changed_line_bucket": "00-02"},
        {"id": "vuln", "pair_key": "p1", "gold": 1, "vuln_probability": 0.12, "changed_line_bucket": "00-02"},
    ]
    hunks = [
        {
            "source_id": "fixed",
            "hunk_rank": 1,
            "header": "@@ fixed @@",
            "removed_preview": ["unsafe_call(x);"],
            "added_preview": ["if (valid) safe_call(x);"],
            "direction_labels": ["candidate_adds_protection"],
            "risk_support": 0,
            "safety_support": 3,
            "pseudo_label": 1,
        },
        {
            "source_id": "vuln",
            "hunk_rank": 1,
            "header": "@@ vuln @@",
            "removed_preview": ["if (valid) safe_call(x);"],
            "added_preview": ["unsafe_call(x);"],
            "direction_labels": ["candidate_introduces_risk"],
            "risk_support": 3,
            "safety_support": 0,
            "pseudo_label": 1,
        },
    ]

    rows, summary = build_dataset(predictions, hunks, top_windows_count=1, confident_gap=0.5)

    assert summary["rows"] == 1
    row = rows[0]
    assert row["side_a_id"] == "fixed"
    assert row["side_b_id"] == "vuln"
    assert row["label"] == "B"
    assert row["is_high_gap_orientation_inversion"] is True
    assert "Side A" in row["contrastive_prompt"]
    assert "Side B" in row["contrastive_prompt"]
    assert row["side_a_windows"][0]["header"] == "@@ fixed @@"


def test_build_dataset_skips_non_mixed_groups() -> None:
    predictions = [
        {"id": "a", "pair_key": "p1", "gold": 1, "vuln_probability": 0.8},
        {"id": "b", "pair_key": "p1", "gold": 1, "vuln_probability": 0.7},
        {"id": "c", "pair_key": "p2", "gold": 1, "vuln_probability": 0.6},
        {"id": "d", "pair_key": "p2", "gold": 0, "vuln_probability": 0.4},
    ]

    rows, summary = build_dataset(predictions, [], top_windows_count=2, confident_gap=0.5)

    assert len(rows) == 1
    assert summary["skipped_non_mixed_groups"] == 1
    assert summary["missing_window_sides"] == 2

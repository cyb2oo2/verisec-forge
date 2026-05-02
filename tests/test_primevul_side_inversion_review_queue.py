from __future__ import annotations

from scripts.build_primevul_side_inversion_review_queue import build_queue, compact_side_windows, summarize


def example(pair_key: str, label: str, score_token: str) -> dict:
    return {
        "pair_key": pair_key,
        "label": label,
        "side_a_id": f"{pair_key}:a",
        "side_b_id": f"{pair_key}:b",
        "side_a_probability": 0.9,
        "side_b_probability": 0.1,
        "probability_gap": 0.8,
        "side_a_windows": [
            {
                "header": "@@ a @@",
                "direction_labels": ["candidate_removes_protection"],
                "risk_support": 3,
                "safety_support": 0,
                "removed_preview": [score_token],
                "added_preview": [],
            }
        ],
        "side_b_windows": [
            {
                "header": "@@ b @@",
                "direction_labels": ["candidate_adds_protection"],
                "risk_support": 0,
                "safety_support": 3,
                "removed_preview": [],
                "added_preview": [score_token],
            }
        ],
        "contrastive_prompt": "prompt",
    }


def test_compact_side_windows_limits_previews() -> None:
    row = example("p1", "A", "x")
    row["side_a_windows"][0]["removed_preview"] = ["1", "2", "3", "4", "5"]

    compact = compact_side_windows(row, "a")

    assert compact[0]["removed_preview"] == ["1", "2", "3", "4"]


def test_summarize_reports_precision() -> None:
    queue = [
        {"seed": 1, "pair_key": "p1", "is_true_inversion_candidate": True},
        {"seed": 1, "pair_key": "p2", "is_true_inversion_candidate": False},
    ]

    summary = summarize(queue, seeds=[1], top_k=2)

    assert summary["precision"] == 0.5
    assert summary["by_seed"][0]["true_inversions"] == 1


def test_build_queue_runs_on_small_dataset() -> None:
    rows = [
        example("p1", "A", "risk_a"),
        example("p2", "B", "risk_b"),
        example("p3", "A", "risk_a"),
        example("p4", "B", "risk_b"),
    ]

    queue, summary = build_queue(
        rows,
        seeds=[1],
        calibration_fraction=0.5,
        epochs=2,
        learning_rate=0.01,
        l2=0.0,
        positive_weight=1.0,
        feature_mode="numeric_text",
        top_k=1,
    )

    assert len(queue) == 1
    assert summary["rows"] == 1

from __future__ import annotations

from scripts.evaluate_primevul_paired_window_side_model import build_report, metric_for_threshold, row_features


def example(pair_key: str, label: str, *, a_token: str, b_token: str) -> dict:
    return {
        "pair_key": pair_key,
        "label": label,
        "probability_gap": 0.8,
        "side_a_probability": 0.9,
        "side_b_probability": 0.1,
        "side_a_windows": [
            {
                "removed_preview": [a_token],
                "added_preview": [],
                "direction_labels": ["candidate_removes_protection"],
                "risk_support": 3,
                "safety_support": 0,
                "protection_delta": -3,
            }
        ],
        "side_b_windows": [
            {
                "removed_preview": [],
                "added_preview": [b_token],
                "direction_labels": ["candidate_adds_protection"],
                "risk_support": 0,
                "safety_support": 3,
                "protection_delta": 3,
            }
        ],
    }


def test_row_features_include_prefixed_window_tokens() -> None:
    features = row_features(example("p1", "A", a_token="dangerous_copy(buffer)", b_token="validate_length(buffer)"))

    assert features["margin_risk_max"] == 3
    assert features["margin_safety_max"] == -3
    assert features["a_removed:dangerous_copy"] == 1
    assert features["b_added:validate_length"] == 1


def test_metric_for_threshold_reports_inversion_recall() -> None:
    metrics = metric_for_threshold(
        [
            {"gold_invert": 1, "inversion_probability": 0.8},
            {"gold_invert": 0, "inversion_probability": 0.2},
        ],
        threshold=0.5,
    )

    assert metrics["balanced_accuracy"] == 1.0
    assert metrics["label_b_recall"] == 1.0


def test_build_report_runs_on_small_contrastive_set() -> None:
    rows = [
        example("p1", "A", a_token="risk_a", b_token="safe_b"),
        example("p2", "B", a_token="safe_a", b_token="risk_b"),
        example("p3", "A", a_token="risk_a", b_token="safe_b"),
        example("p4", "B", a_token="safe_a", b_token="risk_b"),
    ]

    report = build_report(
        rows,
        seeds=[1],
        calibration_fraction=0.5,
        epochs=2,
        learning_rate=0.01,
        l2=0.0,
        positive_weight=1.0,
        thresholds=[0.5],
        selector="balanced_accuracy",
    )

    assert report["summary"]["seeds"] == 1
    assert report["seed_reports"][0]["eval_accuracy"] >= 0.0

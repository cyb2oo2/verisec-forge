from __future__ import annotations

from scripts.evaluate_primevul_contrastive_side_correction import build_multisplit_report, hunk_groups, source_hunk_features


def test_source_hunk_features_aggregate_direction_labels() -> None:
    rows = [
        {"risk_support": 3, "safety_support": 1, "protection_delta": -1, "risk_delta": 2, "direction_labels": ["candidate_introduces_risk"]},
        {"risk_support": 0, "safety_support": 4, "protection_delta": 4, "risk_delta": 0, "direction_labels": ["candidate_adds_protection"]},
    ]

    features = source_hunk_features(rows)

    assert features["risk_max"] == 3
    assert features["safety_max"] == 4
    assert features["candidate_introduces_risk"] == 1
    assert features["candidate_adds_protection"] == 1


def test_contrastive_multisplit_runs_on_small_pair_set() -> None:
    predictions = [
        {"id": "a", "pair_key": "p1", "gold": 1, "pred": 1, "pre_coupled_pred": 1, "vuln_probability": 0.9},
        {"id": "b", "pair_key": "p1", "gold": 0, "pred": 0, "pre_coupled_pred": 0, "vuln_probability": 0.1},
        {"id": "c", "pair_key": "p2", "gold": 1, "pred": 0, "pre_coupled_pred": 1, "vuln_probability": 0.2},
        {"id": "d", "pair_key": "p2", "gold": 0, "pred": 1, "pre_coupled_pred": 0, "vuln_probability": 0.8},
    ]
    hunks = [
        {"source_id": "a", "risk_support": 3, "safety_support": 0, "protection_delta": -1, "risk_delta": 2, "direction_labels": ["candidate_introduces_risk"]},
        {"source_id": "b", "risk_support": 0, "safety_support": 3, "protection_delta": 2, "risk_delta": 0, "direction_labels": ["candidate_adds_protection"]},
        {"source_id": "c", "risk_support": 3, "safety_support": 0, "protection_delta": -1, "risk_delta": 2, "direction_labels": ["candidate_introduces_risk"]},
        {"source_id": "d", "risk_support": 0, "safety_support": 3, "protection_delta": 2, "risk_delta": 0, "direction_labels": ["candidate_adds_protection"]},
    ]

    payload, _ = build_multisplit_report(
        predictions,
        hunks,
        seeds=[1],
        calibration_fraction=0.5,
        epochs=2,
        learning_rate=0.01,
        l2=0.0,
        thresholds=[0.5],
        selector="balanced_accuracy",
    )

    assert payload["summary"]["seeds"] == 1
    assert hunk_groups(hunks)["a"]

from __future__ import annotations

from scripts.evaluate_primevul_time_disjoint_transfer import build_report


def test_time_disjoint_transfer_pair_couples_selected_threshold_rows() -> None:
    metadata = [
        {"id": "vuln", "pair_key": "p1", "cve_year": 2021, "pair_text": "- old\n+ new"},
        {"id": "safe", "pair_key": "p1", "cve_year": 2021, "pair_text": "- old\n+ new"},
    ]
    predictions = [
        {"id": "vuln", "gold": 1, "pred": 0, "vuln_probability": 0.8},
        {"id": "safe", "gold": 0, "pred": 1, "vuln_probability": 0.2},
    ]

    report, rows = build_report(
        metadata,
        predictions,
        default_threshold_report={"balanced_accuracy": 0.0, "vulnerable_recall": 0.0, "safe_specificity": 0.0, "precision": 0.0, "f1": 0.0},
        selected_threshold_report={"threshold": 0.6, "balanced_accuracy": 1.0, "vulnerable_recall": 1.0, "safe_specificity": 1.0, "precision": 1.0, "f1": 1.0},
        threshold=0.6,
        margin=0.02,
    )

    assert report["split"]["cve_years"] == [2021]
    assert report["pair_coupled"]["coupling_counts"]["coupled_groups"] == 1
    assert [row["pred"] for row in rows] == [1, 0]

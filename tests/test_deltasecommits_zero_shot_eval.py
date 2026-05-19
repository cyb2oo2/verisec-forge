from __future__ import annotations

from scripts.evaluate_deltasecommits_zero_shot import build_report


def test_deltasecommits_zero_shot_report_applies_pair_coupling() -> None:
    metadata = [
        {"id": "p1:v", "pair_key": "p1", "has_vulnerability": True, "changed_line_bucket": "03-05"},
        {"id": "p1:s", "pair_key": "p1", "has_vulnerability": False, "changed_line_bucket": "03-05"},
    ]
    predictions = [
        {"id": "p1:v", "gold": 1, "pred": 0, "vuln_probability": 0.9},
        {"id": "p1:s", "gold": 0, "pred": 1, "vuln_probability": 0.2},
    ]

    report = build_report(
        metadata,
        predictions,
        threshold=0.95,
        margin=0.02,
        checkpoint_label="demo",
        scope="demo_scope",
        target_training="demo",
    )

    assert report["split"]["rows"] == 2
    assert report["scope"] == "demo_scope"
    assert report["default_threshold"]["overall"]["balanced_accuracy"] == 0.5
    assert report["pair_coupled"]["overall"]["balanced_accuracy"] == 1.0
    assert report["pair_coupled"]["coupling_counts"]["coupled_groups"] == 1

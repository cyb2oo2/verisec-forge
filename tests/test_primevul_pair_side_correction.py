from __future__ import annotations

from scripts.evaluate_primevul_pair_side_correction import apply_gate, build_report, group_rows, score_groups, train_gate


def test_apply_gate_falls_back_to_pre_coupled_predictions() -> None:
    rows = [
        {"id": "a", "pair_key": "p", "gold": 1, "pred": 0, "pre_coupled_pred": 1, "vuln_probability": 0.1},
        {"id": "b", "pair_key": "p", "gold": 0, "pred": 1, "pre_coupled_pred": 0, "vuln_probability": 0.9},
    ]
    scores = {"p": {"inversion_probability": 0.8}}

    corrected, counts = apply_gate(rows, scores, threshold=0.5)

    assert counts["gated_groups"] == 1
    assert [row["pred"] for row in corrected] == [1, 0]
    assert all(row["side_correction_applied"] for row in corrected)


def test_gate_training_can_score_inversion_like_group() -> None:
    rows = [
        {"id": "a", "pair_key": "bad", "gold": 1, "pred": 0, "pre_coupled_pred": 1, "vuln_probability": 0.1, "changed_lines": 2, "changed_line_bucket": "00-02"},
        {"id": "b", "pair_key": "bad", "gold": 0, "pred": 1, "pre_coupled_pred": 0, "vuln_probability": 0.9, "changed_lines": 2, "changed_line_bucket": "00-02"},
        {"id": "c", "pair_key": "good", "gold": 1, "pred": 1, "pre_coupled_pred": 1, "vuln_probability": 0.9, "changed_lines": 20, "changed_line_bucket": "11-25"},
        {"id": "d", "pair_key": "good", "gold": 0, "pred": 0, "pre_coupled_pred": 0, "vuln_probability": 0.1, "changed_lines": 20, "changed_line_bucket": "11-25"},
    ]
    groups = list(group_rows(rows).values())

    weights = train_gate(groups, epochs=30, learning_rate=0.1, l2=0.0, seed=1)
    scored = {row["pair_key"]: row for row in score_groups(groups, weights)}

    assert scored["bad"]["inversion_probability"] > scored["good"]["inversion_probability"]


def test_build_report_keeps_eval_split_separate() -> None:
    rows = [
        {"id": "a1", "pair_key": "p1", "gold": 1, "pred": 1, "pre_coupled_pred": 1, "vuln_probability": 0.9, "changed_lines": 2, "changed_line_bucket": "00-02"},
        {"id": "a2", "pair_key": "p1", "gold": 0, "pred": 0, "pre_coupled_pred": 0, "vuln_probability": 0.1, "changed_lines": 2, "changed_line_bucket": "00-02"},
        {"id": "b1", "pair_key": "p2", "gold": 1, "pred": 0, "pre_coupled_pred": 1, "vuln_probability": 0.2, "changed_lines": 5, "changed_line_bucket": "03-05"},
        {"id": "b2", "pair_key": "p2", "gold": 0, "pred": 1, "pre_coupled_pred": 0, "vuln_probability": 0.8, "changed_lines": 5, "changed_line_bucket": "03-05"},
    ]

    report, corrected = build_report(
        rows,
        calibration_fraction=0.5,
        seed=1,
        epochs=5,
        learning_rate=0.01,
        l2=0.0,
        thresholds=[0.5],
        selector="balanced_accuracy",
    )

    assert report["split"]["calibration_pair_count"] == 1
    assert report["split"]["eval_pair_count"] == 1
    assert len(corrected) == 2

from __future__ import annotations

from scripts.analyze_joint_pairwise_selective_calibration import (
    calibration_metrics,
    select_margin,
    select_temperature,
    selective_metrics,
    split_rows,
)


def _row(key: str, safe: float, vulnerable: float, correct: bool) -> dict:
    return {
        "pair_key": key,
        "safe_candidate_probability": safe,
        "vulnerable_candidate_probability": vulnerable,
        "correct_orientation": correct,
    }


def test_split_rows_is_pair_key_disjoint() -> None:
    rows = [_row(str(index), 0.1, 0.9, True) for index in range(10)]
    calibration, evaluation = split_rows(rows, calibration_fraction=0.3, seed=7)

    assert len(calibration) == 3
    assert len(evaluation) == 7
    assert {row["pair_key"] for row in calibration}.isdisjoint(
        {row["pair_key"] for row in evaluation}
    )


def test_select_margin_respects_minimum_coverage() -> None:
    rows = [
        _row("strong-correct", 0.1, 0.9, True),
        _row("medium-correct", 0.3, 0.7, True),
        _row("weak-wrong", 0.51, 0.49, False),
        _row("weak-correct", 0.48, 0.52, True),
    ]

    result = select_margin(rows, margins=[0.0, 0.05, 0.3], minimum_coverage=0.5)

    assert result["selected"]["margin"] == 0.05
    assert result["selected"]["coverage"] == 0.5
    assert result["selected"]["accepted_accuracy"] == 1.0


def test_selective_metrics_capture_low_margin_error() -> None:
    rows = [
        _row("correct", 0.1, 0.9, True),
        _row("wrong", 0.51, 0.49, False),
    ]

    metrics = selective_metrics(rows, margin=0.1)

    assert metrics["coverage"] == 0.5
    assert metrics["accepted_accuracy"] == 1.0
    assert metrics["error_capture_rate"] == 1.0


def test_temperature_is_selected_on_correctness_nll() -> None:
    rows = [
        _row("correct", 0.1, 0.9, True),
        _row("wrong", 0.2, 0.8, False),
    ]

    selected = select_temperature(rows, temperatures=[0.5, 1.0, 2.0, 4.0])
    metrics = calibration_metrics(rows, temperature=selected["temperature"])

    assert selected["temperature"] == 4.0
    assert metrics["brier"] >= 0.0

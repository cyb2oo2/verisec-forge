from scripts.analyze_learned_content_routed_system_statistics import (
    bootstrap_delta,
    bootstrap_system,
    group_sign_test,
    mcnemar,
)


def row(row_id: str, pair_key: str, gold: int, pred: int, prob: float) -> dict:
    return {
        "id": row_id,
        "pair_key": pair_key,
        "gold": gold,
        "pred": pred,
        "vuln_probability": prob,
    }


def test_bootstrap_system_resamples_pair_groups() -> None:
    rows = [
        row("p1-v", "p1", 1, 1, 0.9),
        row("p1-s", "p1", 0, 0, 0.1),
        row("p2-v", "p2", 1, 1, 0.8),
        row("p2-s", "p2", 0, 0, 0.2),
    ]

    report = bootstrap_system(rows, metric="balanced_accuracy", iterations=20, seed=7)

    assert report["observed"] == 1.0
    assert report["units"] == 2
    assert report["ci95_low"] == 1.0
    assert report["ci95_high"] == 1.0


def test_delta_and_paired_tests_compare_same_rows() -> None:
    baseline = [
        row("p1-v", "p1", 1, 0, 0.4),
        row("p1-s", "p1", 0, 0, 0.2),
    ]
    candidate = [
        row("p1-v", "p1", 1, 1, 0.8),
        row("p1-s", "p1", 0, 0, 0.1),
    ]

    delta = bootstrap_delta(baseline, candidate, metric="balanced_accuracy", iterations=20, seed=11)
    row_test = mcnemar(baseline, candidate)
    group_test = group_sign_test(baseline, candidate, metric="group_all_correct_rate")

    assert delta["observed_delta"] == 0.5
    assert row_test["candidate_correct_baseline_wrong"] == 1
    assert row_test["candidate_wrong_baseline_correct"] == 0
    assert group_test["wins"] == 1
    assert group_test["losses"] == 0

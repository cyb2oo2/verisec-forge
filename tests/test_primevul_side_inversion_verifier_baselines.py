from __future__ import annotations

from scripts.evaluate_primevul_side_inversion_verifier_baselines import build_report, evidence_score, metric


def row(*, accept: bool, prompt: str = "", score: float = 0.8) -> dict:
    return {
        "accept_flip": accept,
        "side_model_score": score,
        "prompt": prompt,
    }


def test_evidence_score_rewards_risky_b_and_safe_a() -> None:
    prompt = "\n".join(
        [
            "Side A windows:",
            "Signals: risk=0 safety=3 labels=candidate_adds_protection",
            "Side B windows:",
            "Signals: risk=5 safety=0 labels=candidate_removes_protection",
        ]
    )

    assert evidence_score(row(accept=True, prompt=prompt)) == 8.0


def test_metric_counts_accept_flip_class() -> None:
    rows = [row(accept=True), row(accept=False), row(accept=False)]
    result = metric(rows, [1, 0, 1], name="toy")

    assert result["tp"] == 1
    assert result["tn"] == 1
    assert result["fp"] == 1
    assert result["fn"] == 0
    assert result["accept_precision"] == 0.5


def test_build_report_includes_best_summaries() -> None:
    rows = [
        row(accept=True, score=0.95, prompt="Side A windows:\nSignals: risk=0 safety=3\nSide B windows:\nSignals: risk=4 safety=0"),
        row(accept=False, score=0.7, prompt="Side A windows:\nSignals: risk=4 safety=0\nSide B windows:\nSignals: risk=0 safety=3"),
    ]

    report = build_report(rows, score_thresholds=[0.9], evidence_thresholds=[0.0])

    assert report["summary"]["rows"] == 2
    assert report["summary"]["best_balanced_accuracy"]["balanced_accuracy"] == 1.0

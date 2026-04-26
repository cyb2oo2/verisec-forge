from __future__ import annotations

from vrf.support_scoring import analyze_detector_scorer_failures, evaluate_detector_scorer


def test_evaluate_detector_scorer_applies_second_stage_gate() -> None:
    dataset_rows = {
        "vuln-supported": {"id": "vuln-supported", "has_vulnerability": True},
        "vuln-missed": {"id": "vuln-missed", "has_vulnerability": True},
        "safe-rejected": {"id": "safe-rejected", "has_vulnerability": False},
        "safe-ignored": {"id": "safe-ignored", "has_vulnerability": False},
    }
    probability_rows = {
        "vuln-supported": {"id": "vuln-supported", "vuln_probability": 0.9},
        "vuln-missed": {"id": "vuln-missed", "vuln_probability": 0.4},
        "safe-rejected": {"id": "safe-rejected", "vuln_probability": 0.8},
        "safe-ignored": {"id": "safe-ignored", "vuln_probability": 0.1},
    }
    scorer_rows = {
        "vuln-supported": {"id": "vuln-supported", "supported_probability": 0.7},
        "safe-rejected": {"id": "safe-rejected", "supported_probability": 0.4},
    }

    report = evaluate_detector_scorer(
        dataset_rows=dataset_rows,
        probability_rows=probability_rows,
        scorer_rows=scorer_rows,
        detector_threshold=0.5,
        scorer_threshold=0.5,
    )

    assert report["tp"] == 1
    assert report["tn"] == 2
    assert report["fp"] == 0
    assert report["fn"] == 1
    assert report["detector_positive_rate"] == 0.5
    assert report["scorer_positive_rate"] == 0.25
    assert report["scorer_acceptance_rate_on_detector_positive"] == 0.5
    assert report["scorer_rejection_rate_on_detector_positive"] == 0.5
    assert report["is_pass_through"] is False
    assert report["scorer_behavior"] == "filtering"
    assert report["presence_accuracy"] == 0.75
    assert report["vulnerable_recall"] == 0.5
    assert report["safe_specificity"] == 1.0
    assert report["precision"] == 1.0
    assert report["f1"] == 0.6667
    assert report["detector_only"]["f1"] == 0.5
    assert report["delta_vs_detector_only"]["f1"] == 0.1667


def test_evaluate_detector_scorer_reports_unsupported_positive_share() -> None:
    dataset_rows = {
        "vuln-supported": {"id": "vuln-supported", "has_vulnerability": True},
        "safe-supported": {"id": "safe-supported", "has_vulnerability": False},
    }
    probability_rows = {
        "vuln-supported": {"id": "vuln-supported", "vuln_probability": 0.9},
        "safe-supported": {"id": "safe-supported", "vuln_probability": 0.8},
    }
    scorer_rows = {
        "vuln-supported": {"id": "vuln-supported", "supported_probability": 0.9},
        "safe-supported": {"id": "safe-supported", "vuln_probability": 0.8},
    }

    report = evaluate_detector_scorer(
        dataset_rows=dataset_rows,
        probability_rows=probability_rows,
        scorer_rows=scorer_rows,
        detector_threshold=0.5,
        scorer_threshold=0.5,
    )

    assert report["tp"] == 1
    assert report["fp"] == 1
    assert report["unsupported_positive_share"] == 0.5
    assert report["precision"] == 0.5
    assert report["is_pass_through"] is True
    assert report["scorer_behavior"] == "pass_through"
    assert report["delta_vs_detector_only"]["f1"] == 0.0


def test_evaluate_detector_scorer_flags_weak_filter_behavior() -> None:
    dataset_rows = {
        str(index): {"id": str(index), "has_vulnerability": index < 10}
        for index in range(20)
    }
    probability_rows = {
        str(index): {"id": str(index), "vuln_probability": 0.9}
        for index in range(20)
    }
    scorer_rows = {
        str(index): {"id": str(index), "supported_probability": 0.9}
        for index in range(20)
    }
    scorer_rows["19"] = {"id": "19", "supported_probability": 0.1}

    report = evaluate_detector_scorer(
        dataset_rows=dataset_rows,
        probability_rows=probability_rows,
        scorer_rows=scorer_rows,
        detector_threshold=0.5,
        scorer_threshold=0.5,
    )

    assert report["scorer_acceptance_rate_on_detector_positive"] == 0.95
    assert report["is_pass_through"] is False
    assert report["scorer_behavior"] == "weak_filter"


def test_detector_scorer_failure_buckets_separate_detector_and_scorer_misses() -> None:
    dataset_rows = {
        "tp": {"id": "tp", "has_vulnerability": True},
        "fn-detector": {"id": "fn-detector", "has_vulnerability": True},
        "fn-scorer": {"id": "fn-scorer", "has_vulnerability": True},
        "fp": {"id": "fp", "has_vulnerability": False},
        "tn-detector": {"id": "tn-detector", "has_vulnerability": False},
        "tn-scorer": {"id": "tn-scorer", "has_vulnerability": False},
    }
    probability_rows = {
        "tp": {"id": "tp", "vuln_probability": 0.9},
        "fn-detector": {"id": "fn-detector", "vuln_probability": 0.1},
        "fn-scorer": {"id": "fn-scorer", "vuln_probability": 0.9},
        "fp": {"id": "fp", "vuln_probability": 0.9},
        "tn-detector": {"id": "tn-detector", "vuln_probability": 0.1},
        "tn-scorer": {"id": "tn-scorer", "vuln_probability": 0.9},
    }
    scorer_rows = {
        "tp": {"id": "tp", "supported_probability": 0.9},
        "fn-scorer": {"id": "fn-scorer", "supported_probability": 0.1},
        "fp": {"id": "fp", "supported_probability": 0.9},
        "tn-scorer": {"id": "tn-scorer", "supported_probability": 0.1},
    }

    report = analyze_detector_scorer_failures(
        dataset_rows=dataset_rows,
        probability_rows=probability_rows,
        scorer_rows=scorer_rows,
        detector_threshold=0.5,
        scorer_threshold=0.5,
    )

    assert report["counts"]["true_positive_supported"] == 1
    assert report["counts"]["false_negative_detector_miss"] == 1
    assert report["counts"]["false_negative_scorer_reject"] == 1
    assert report["counts"]["false_positive_supported_safe"] == 1
    assert report["counts"]["true_negative_detector_reject"] == 1
    assert report["counts"]["true_negative_scorer_reject"] == 1
    assert report["rates"]["false_negative_detector_miss_share"] == 0.5
    assert report["rates"]["true_negative_scorer_reject_share"] == 0.5

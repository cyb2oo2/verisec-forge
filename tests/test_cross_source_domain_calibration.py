from scripts.build_cross_source_domain_calibration import build_report


def _threshold_report(rows):
    return {
        "thresholds": rows,
        "best_by_balanced_accuracy": max(rows, key=lambda row: row["balanced_accuracy"]),
    }


def test_source_aware_calibration_can_beat_shared_threshold():
    prime_rows = [
        {"threshold": 0.3, "balanced_accuracy": 0.8, "vulnerable_recall": 0.7, "safe_specificity": 0.9, "precision": 0.8, "f1": 0.75, "tp": 7, "tn": 9, "fp": 1, "fn": 3},
        {"threshold": 0.4, "balanced_accuracy": 0.9, "vulnerable_recall": 0.9, "safe_specificity": 0.9, "precision": 0.9, "f1": 0.9, "tp": 9, "tn": 9, "fp": 1, "fn": 1},
    ]
    delta_rows = [
        {"threshold": 0.3, "balanced_accuracy": 0.9, "vulnerable_recall": 0.9, "safe_specificity": 0.9, "precision": 0.9, "f1": 0.9, "tp": 9, "tn": 9, "fp": 1, "fn": 1},
        {"threshold": 0.4, "balanced_accuracy": 0.8, "vulnerable_recall": 0.9, "safe_specificity": 0.7, "precision": 0.75, "f1": 0.8, "tp": 9, "tn": 7, "fp": 3, "fn": 1},
    ]
    pair_report = {
        "pair_coupled": {
            "overall": {"balanced_accuracy": 0.88},
            "group_metrics": {"group_all_correct_rate": 0.8, "orientation_accuracy": 0.9},
        }
    }

    report = build_report(
        prime_threshold_report=_threshold_report(prime_rows),
        delta_threshold_report=_threshold_report(delta_rows),
        prime_pair_report=pair_report,
        delta_pair_report=pair_report,
    )

    assert report["best_global_threshold"]["threshold"] in {0.3, 0.4}
    assert report["source_aware_thresholds"]["primevul_time_threshold"] == 0.4
    assert report["source_aware_thresholds"]["deltasecommits_threshold"] == 0.3
    assert report["source_aware_minus_best_global"]["balanced_accuracy"] > 0

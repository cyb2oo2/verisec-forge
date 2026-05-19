from scripts.build_patcheval_adapter_multiseed_report import build_report


def _pair_report(default_ba, pair_ba, default_group, pair_group):
    return {
        "protocol": {"checkpoint": "ckpt"},
        "default_threshold": {
            "overall": {
                "balanced_accuracy": default_ba,
                "f1": default_ba,
            },
            "group_metrics": {
                "group_all_correct_rate": default_group,
                "orientation_accuracy": default_group,
            },
        },
        "pair_coupled": {
            "overall": {
                "balanced_accuracy": pair_ba,
                "vulnerable_recall": pair_ba,
                "safe_specificity": pair_ba,
                "precision": pair_ba,
                "f1": pair_ba,
            },
            "group_metrics": {
                "group_all_correct_rate": pair_group,
                "orientation_accuracy": pair_group,
            },
        },
    }


def _threshold_report(best_ba, threshold):
    return {
        "best_by_balanced_accuracy": {"balanced_accuracy": best_ba, "threshold": threshold},
        "best_by_f1": {"f1": best_ba, "threshold": threshold},
    }


def test_patcheval_multiseed_report_summarizes_seed_variance_and_delta():
    payload = build_report(
        pair_reports={
            "1": _pair_report(0.7, 0.8, 0.6, 0.7),
            "2": _pair_report(0.8, 0.9, 0.7, 0.8),
        },
        threshold_reports={
            "1": _threshold_report(0.81, 0.5),
            "2": _threshold_report(0.91, 0.4),
        },
    )

    assert payload["status"] == "ok"
    assert payload["summary"]["pair_coupled_balanced_accuracy"]["mean"] == 0.85
    assert payload["summary"]["pair_coupled_balanced_accuracy"]["range"] == 0.1
    assert payload["summary"]["pair_coupled_minus_default_ba"]["mean"] == 0.1
    assert payload["seeds"][0]["best_threshold"] == 0.5

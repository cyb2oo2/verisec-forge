from scripts.build_source_aware_mixture_report import build_report


def _report(ba_counts, group_correct, orientation_correct, *, checkpoint):
    tp, tn, fp, fn = ba_counts
    pair_count = group_correct + 1
    return {
        "protocol": {"checkpoint": checkpoint},
        "pair_coupled": {
            "overall": {
                "tp": tp,
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "balanced_accuracy": 0.0,
                "vulnerable_recall": 0.0,
                "safe_specificity": 0.0,
                "precision": 0.0,
                "f1": 0.0,
            },
            "group_metrics": {
                "unique_pair_count": pair_count,
                "group_all_correct": group_correct,
                "orientation_eligible_pair_count": pair_count,
                "orientation_correct": orientation_correct,
            },
        },
    }


def test_source_routed_mixture_reports_positive_delta():
    matched_prime = _report((8, 8, 2, 2), 7, 7, checkpoint="matched")
    matched_delta = _report((7, 7, 3, 3), 6, 6, checkpoint="matched")
    expert_prime = _report((9, 9, 1, 1), 8, 8, checkpoint="prime")
    expert_delta = _report((8, 8, 2, 2), 7, 7, checkpoint="delta")

    payload = build_report(
        matched_prime_report=matched_prime,
        matched_delta_report=matched_delta,
        expert_prime_report=expert_prime,
        expert_delta_report=expert_delta,
    )

    assert payload["systems"][1]["system"] == "source-routed expert mixture"
    assert payload["routed_minus_single"]["balanced_accuracy"] > 0
    assert payload["routed_minus_single"]["group_all_correct_rate"] > 0

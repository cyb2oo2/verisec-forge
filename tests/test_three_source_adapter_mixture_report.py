from scripts.build_three_source_adapter_mixture_report import build_report


def _report(tp, tn, fp, fn, group_correct, orientation_correct, *, checkpoint):
    pair_count = group_correct + 2
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


def test_three_source_mixture_uses_patch_fallback_and_reports_delta():
    matched_prime = _report(8, 8, 2, 2, 7, 7, checkpoint="matched")
    matched_delta = _report(7, 7, 3, 3, 6, 6, checkpoint="matched")
    matched_patch = _report(6, 6, 4, 4, 5, 5, checkpoint="matched")
    expert_prime = _report(9, 9, 1, 1, 8, 8, checkpoint="prime")
    expert_delta = _report(8, 8, 2, 2, 7, 7, checkpoint="delta")

    payload = build_report(
        matched_prime_report=matched_prime,
        matched_delta_report=matched_delta,
        matched_patch_report=matched_patch,
        expert_prime_report=expert_prime,
        expert_delta_report=expert_delta,
    )

    routed_patch = payload["systems"][1]["sources"][2]
    assert routed_patch["source"] == "PatchEval"
    assert routed_patch["adapter"] == "matched-mixed fallback"
    assert payload["routed_minus_single"]["balanced_accuracy"] > 0

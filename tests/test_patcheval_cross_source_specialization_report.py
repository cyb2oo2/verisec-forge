from scripts.build_patcheval_cross_source_specialization_report import build_report


def _pair_report(default_ba, pair_ba, group=0.7, orientation=0.8):
    return {
        "default_threshold": {"overall": {"balanced_accuracy": default_ba}},
        "pair_coupled": {
            "overall": {"balanced_accuracy": pair_ba},
            "group_metrics": {
                "group_all_correct_rate": group,
                "orientation_accuracy": orientation,
            },
        },
    }


def _threshold_report(best_ba, threshold):
    return {"best_by_balanced_accuracy": {"balanced_accuracy": best_ba, "threshold": threshold}}


def test_cross_source_specialization_reports_gaps_to_source_experts():
    payload = build_report(
        patch_on_prime=_pair_report(0.7, 0.8),
        patch_on_delta=_pair_report(0.72, 0.82),
        patch_on_patch=_pair_report(0.78, 0.84),
        patch_multiseed={
            "summary": {
                "pair_coupled_balanced_accuracy": {
                    "mean": 0.83,
                    "min": 0.81,
                    "max": 0.85,
                }
            }
        },
        prime_expert=_pair_report(0.75, 0.85),
        delta_expert=_pair_report(0.77, 0.86),
        patch_zero_shot=_pair_report(0.76, 0.8),
        prime_threshold=_threshold_report(0.79, 0.6),
        delta_threshold=_threshold_report(0.81, 0.7),
    )

    assert payload["status"] == "ok"
    assert payload["datasets"][0]["patcheval_minus_source_expert_ba"] == -0.05
    assert payload["datasets"][1]["patcheval_minus_source_expert_ba"] == -0.04
    assert payload["datasets"][2]["patcheval_minus_matched_mixed_ba"] == 0.04
    assert payload["cross_source_summary"]["mean_cross_source_gap_to_source_expert_ba"] == -0.045

from scripts.build_learned_router_claim_boundary_report import build_report


def test_claim_boundary_summary_extracts_core_claims() -> None:
    stats = {
        "deltas": {
            "single matched-mixed checkpoint": {
                "balanced_accuracy": {"observed_delta": 0.0073, "ci95_low": 0.0, "ci95_high": 0.0145},
                "group_all_correct_rate": {"observed_delta": 0.0066, "ci95_low": -0.0015, "ci95_high": 0.0147},
            }
        },
        "paired_tests": {
            "single matched-mixed checkpoint": {
                "balanced_accuracy": {"two_sided_p_value": 0.024461},
            }
        },
    }
    leave_one = {
        "heldout_results": [
            {"heldout_source": "A", "deltas": {"routed_minus_oracle": {"balanced_accuracy": -0.02}}},
            {"heldout_source": "B", "deltas": {"routed_minus_oracle": {"balanced_accuracy": -0.01}}},
        ]
    }
    feature = {
        "feature_results": [
            {
                "feature_mode": "char_3_5",
                "routing_metrics": {"row_accuracy": 0.9},
                "systems": [{}, {}, {"overall": {"balanced_accuracy": 0.8664}}],
                "deltas": {"routed_minus_single": {"balanced_accuracy": 0.0073}},
            },
            {
                "feature_mode": "token_1_2",
                "routing_metrics": {"row_accuracy": 0.7},
                "systems": [{}, {}, {"overall": {"balanced_accuracy": 0.8627}}],
                "deltas": {"routed_minus_single": {"balanced_accuracy": 0.0036}},
            },
            {
                "feature_mode": "diff_line_markers",
                "routing_metrics": {"row_accuracy": 0.78},
                "systems": [{}, {}, {"overall": {"balanced_accuracy": 0.8649}}],
                "deltas": {"routed_minus_single": {"balanced_accuracy": 0.0058}},
            },
        ]
    }

    payload = build_report(stats_payload=stats, leave_one_payload=leave_one, feature_payload=feature)

    assert payload["status"] == "ok"
    assert payload["closed_world_statistical_support"]["learned_minus_single_ba"] == 0.0073
    assert payload["leave_one_source_boundary"]["worst_delta_vs_oracle_ba"] == -0.02
    assert payload["feature_ablation"]["diff_line_markers"]["routed_ba"] == 0.8649

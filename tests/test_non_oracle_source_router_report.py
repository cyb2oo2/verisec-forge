from scripts.build_non_oracle_source_router_report import build_report, infer_source_without_label


def _report(tp, tn, fp, fn, group_correct, orientation_correct):
    pair_count = group_correct + 1
    return {
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
        }
    }


def test_non_oracle_source_router_ignores_explicit_source_label():
    assert infer_source_without_label({"source_dataset": "ByteDance/PatchEval", "programming_language": "Go"}) == "PatchEval"
    assert infer_source_without_label({"source_dataset": "wrong", "file_extension": "cc"}) == "DeltaSecommits"
    assert infer_source_without_label({"source_dataset": "wrong", "cve_year": 2022, "file_name": "x.c"}) == "PrimeVul-time"


def test_non_oracle_source_router_matches_oracle_when_metadata_schema_is_separable():
    payload = build_report(
        prime_metadata=[{"pair_key": "p1", "cve_year": 2022}],
        delta_metadata=[{"pair_key": "d1", "file_extension": "cpp"}],
        patch_metadata=[{"pair_key": "e1", "programming_language": "Python"}],
        matched_prime_report=_report(8, 8, 2, 2, 7, 7),
        matched_delta_report=_report(7, 7, 3, 3, 6, 6),
        matched_patch_report=_report(6, 6, 4, 4, 5, 5),
        expert_prime_report=_report(9, 9, 1, 1, 8, 8),
        expert_delta_report=_report(8, 8, 2, 2, 7, 7),
        expert_patch_report=_report(7, 7, 3, 3, 6, 6),
    )

    assert payload["routing_metrics"]["row_accuracy"] == 1.0
    assert payload["automatic_minus_oracle"]["balanced_accuracy"] == 0.0
    assert payload["automatic_minus_single"]["balanced_accuracy"] > 0

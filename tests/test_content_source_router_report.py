from scripts.build_content_source_router_report import (
    build_report,
    infer_source_from_diff_body,
    infer_source_from_surface_text,
)


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


def test_surface_router_uses_prompt_text_not_row_metadata():
    assert infer_source_from_surface_text("Project: https://github.com/x/y\nLanguage: Go\nUnified diff:\nfunc f() {}") == "PatchEval"
    assert infer_source_from_surface_text("Project: https://github.com/tensorflow/tensorflow\nCVE: GHSA-1\nUnified diff:") == "DeltaSecommits"
    assert infer_source_from_surface_text("Project: linux\nCVE: CVE-2022-1\nUnified diff:") == "PrimeVul-time"


def test_diff_body_router_is_stricter_and_keyword_based():
    assert infer_source_from_diff_body("Unified diff:\n+func main() { err := nil }") == "PatchEval"
    assert infer_source_from_diff_body("Unified diff:\n+OP_REQUIRES(c, errors::InvalidArgument(\"x\"));") == "DeltaSecommits"
    assert infer_source_from_diff_body("Unified diff:\n+ut64 x = sizeof(struct foo); goto fail;") == "PrimeVul-time"


def test_content_source_router_reports_surface_system_when_surface_routing_is_perfect():
    payload = build_report(
        prime_metadata=[{"pair_key": "p1", "pair_text": "Project: linux\nUnified diff:\n+ut64 x;"}],
        delta_metadata=[{"pair_key": "d1", "pair_text": "Project: https://github.com/tensorflow/tensorflow\nUnified diff:\n+std::string x;"}],
        patch_metadata=[{"pair_key": "e1", "pair_text": "Language: Go\nUnified diff:\n+func f() {}"}],
        matched_prime_report=_report(8, 8, 2, 2, 7, 7),
        matched_delta_report=_report(7, 7, 3, 3, 6, 6),
        matched_patch_report=_report(6, 6, 4, 4, 5, 5),
        expert_prime_report=_report(9, 9, 1, 1, 8, 8),
        expert_delta_report=_report(8, 8, 2, 2, 7, 7),
        expert_patch_report=_report(7, 7, 3, 3, 6, 6),
    )

    assert payload["routing_metrics"]["surface_content"]["row_accuracy"] == 1.0
    assert payload["systems"]["surface_content_router"] is not None
    assert payload["surface_minus_oracle"]["balanced_accuracy"] == 0.0


def test_content_source_router_does_not_fallback_to_oracle_when_surface_routing_is_imperfect():
    payload = build_report(
        prime_metadata=[{"pair_key": "p1", "pair_text": "Project: linux\nUnified diff:\n+ut64 x;"}],
        delta_metadata=[{"pair_key": "d1", "pair_text": "Project: https://github.com/tensorflow/tensorflow\nUnified diff:\n+std::string x;"}],
        patch_metadata=[{"pair_key": "e1", "pair_text": "Project: https://github.com/owner/repo\nUnified diff:\n+func f() {}"}],
        matched_prime_report=_report(8, 8, 2, 2, 7, 7),
        matched_delta_report=_report(7, 7, 3, 3, 6, 6),
        matched_patch_report=_report(6, 6, 4, 4, 5, 5),
        expert_prime_report=_report(9, 9, 1, 1, 8, 8),
        expert_delta_report=_report(8, 8, 2, 2, 7, 7),
        expert_patch_report=_report(7, 7, 3, 3, 6, 6),
    )

    assert payload["routing_metrics"]["surface_content"]["row_accuracy"] < 1.0
    assert payload["systems"]["surface_content_router"] is None
    assert payload["surface_minus_single"]["balanced_accuracy"] is None
    assert payload["surface_minus_oracle"]["balanced_accuracy"] is None

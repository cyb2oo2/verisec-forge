from vrf.counterfactuals import (
    build_interventions,
    evaluate_intervention_predictions,
    normalize_code_identifiers,
    strip_metadata,
)


def test_counterfactual_interventions_declare_expected_relations():
    row = {
        "id": "safe",
        "pair_key": "pair",
        "has_vulnerability": False,
        "pair_text": "Project: demo\nCVE: CVE-1\nUnified diff:\n-old_name\n+new_name",
    }
    counterpart = {
        "id": "vuln",
        "has_vulnerability": True,
        "pair_text": "Project: demo\nCVE: CVE-1\nUnified diff:\n-new_name\n+old_name",
    }
    by_name = {item["intervention"]: item for item in build_interventions(row, counterpart)}
    assert "Project:" not in strip_metadata(row["pair_text"])
    assert by_name["metadata_removed"]["expected_relation"] == "invariant"
    assert by_name["side_order_swapped"]["expected_relation"] == "equivariant_flip"
    assert by_name["side_order_swapped"]["expected_label"] == 1
    assert by_name["context_truncated"]["expected_relation"] == "abstention_sensitivity"


def test_counterfactual_evaluator_reports_unexpected_changes():
    rows = [
        {"intervention": "metadata_removed", "expected_relation": "invariant", "base_pred": 1, "intervention_pred": 1},
        {"intervention": "metadata_removed", "expected_relation": "invariant", "base_pred": 1, "intervention_pred": 0},
        {"intervention": "side_order_swapped", "expected_relation": "equivariant_flip", "base_pred": 1, "intervention_pred": 0},
    ]
    report = evaluate_intervention_predictions(rows)
    assert report["by_intervention"]["metadata_removed"]["unexpected_change_rate"] == 0.5
    assert report["by_intervention"]["side_order_swapped"]["relation_success_rate"] == 1.0
    assert report["by_intervention"]["metadata_removed"]["unexpected_change_ci95"][0] < 0.5
    assert report["by_intervention"]["metadata_removed"]["flip_1_to_0"] == 1


def test_identifier_normalization_preserves_instruction_and_diff_structure():
    text = (
        "Task: compare two versions.\n"
        "Predict which Side contains the vulnerability.\n\n"
        "--- Side A\n+++ Side B\n@@ -1 +1 @@\n-old_name(value)\n+new_name(value)"
    )

    normalized = normalize_code_identifiers(text)

    assert "Task: compare two versions." in normalized
    assert "Predict which Side" in normalized
    assert "--- Side A\n+++ Side B\n@@ -1 +1 @@" in normalized
    assert "old_name" not in normalized
    assert "new_name" not in normalized
    assert "-id_1(id_2)" in normalized

from vrf.qwen_mechanism_analysis import (
    analyze_length,
    changed_line_bucket,
    changed_line_count,
    compare_lengths,
    join_predictions,
    prediction_independence,
)


def row(row_id, variant, gold, predicted, *, truncated=False, relation="invariant"):
    return {
        "id": row_id,
        "dataset": "primevul",
        "pair_key": "pair-1",
        "audit_variant": variant,
        "expected_relation": relation,
        "gold_riskier_side": gold,
        "predicted_riskier_side": predicted,
        "supports_abstention": False,
        "text": (
            "Unified diff from Side A to Side B:\n"
            "--- Side A\n+++ Side B\n@@\n-old();\n+new();\n"
        ),
        "runtime_accounting": {
            "critical_hunk_truncated": truncated,
            "transformation_introduced_critical_truncation": False,
            "token_count": 20,
        },
    }


def test_join_predictions_requires_exact_ids():
    runtime = [{"id": "a", "value": 1}]
    predictions = [{"id": "a", "predicted_riskier_side": "A"}]
    assert join_predictions(runtime, predictions)[0]["value"] == 1


def test_analysis_separates_accuracy_and_relation():
    rows = [
        row("base", "canonical", "A", "A"),
        row("swap", "side_swap", "B", "B", relation="equivariant_swap"),
        row("pad", "padding_post_diff", "A", "B"),
    ]
    report = analyze_length(rows, max_length=512)
    assert report["variants"]["canonical"]["accuracy"] == 1.0
    assert report["variants"]["side_swap"]["relation_accuracy"] == 1.0
    assert report["variants"]["padding_post_diff"]["accuracy"] == 0.0
    assert report["variants"]["padding_post_diff"]["a_to_b"] == 1
    assert report["supports_abstention"] is False


def test_training_contract_swap_uses_training_prompt_as_reference():
    rows = [
        row("base", "canonical", "A", "A"),
        row("train", "training_prompt", "A", "B"),
        row(
            "train-swap",
            "training_prompt_side_swap",
            "B",
            "A",
            relation="equivariant_swap",
        ),
    ]
    report = analyze_length(rows, max_length=512)

    assert (
        report["variants"]["training_prompt_side_swap"]["relation_accuracy"]
        == 1.0
    )


def test_compare_lengths_counts_repairs_and_regressions():
    short = [
        row("base", "canonical", "A", "B"),
        row("pad", "padding_post_diff", "A", "A"),
    ]
    long = [
        row("base", "canonical", "A", "A"),
        row("pad", "padding_post_diff", "A", "B"),
    ]
    comparison = compare_lengths(short, long)
    assert comparison["canonical"]["repaired_at_1024"] == 1
    assert comparison["padding_post_diff"]["introduced_at_1024"] == 1


def test_changed_line_accounting_ignores_file_headers():
    text = (
        "Unified diff from Side A to Side B:\n"
        "--- Side A\n+++ Side B\n@@\n-old();\n+new();\n"
    )
    assert changed_line_count(text) == 2
    assert changed_line_bucket(2) == "00-02"


def test_prediction_independence_detects_perfect_correlation():
    baseline = {"p1": "A", "p2": "A", "p3": "B", "p4": "B"}
    matched = {"p1": "A", "p2": "A", "p3": "B", "p4": "B"}

    result = prediction_independence(baseline, matched)

    assert result["n"] == 4
    assert result["phi"] == 1.0
    assert result["p_value"] < 0.05


def test_prediction_independence_detects_perfect_anticorrelation():
    baseline = {"p1": "A", "p2": "A", "p3": "B", "p4": "B"}
    flipped = {"p1": "B", "p2": "B", "p3": "A", "p4": "A"}

    result = prediction_independence(baseline, flipped)

    assert result["phi"] == -1.0
    assert result["p_value"] < 0.05


def test_prediction_independence_detects_no_correlation():
    # Balanced, evenly distributed across all four quadrants -> independent.
    baseline = {"p1": "A", "p2": "A", "p3": "B", "p4": "B"}
    independent = {"p1": "A", "p2": "B", "p3": "A", "p4": "B"}

    result = prediction_independence(baseline, independent)

    assert result["phi"] == 0.0
    assert result["p_value"] == 1.0


def test_prediction_independence_handles_degenerate_single_class():
    # If one side never reaches "first", the chi-square test is undefined.
    baseline = {"p1": "A", "p2": "A"}
    other = {"p1": "A", "p2": "B"}

    result = prediction_independence(baseline, other)

    assert result["n"] == 2
    assert result["chi2"] is None
    assert result["phi"] is None
    assert result["p_value"] is None

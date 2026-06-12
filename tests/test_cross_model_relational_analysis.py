from vrf.cross_model_relational_analysis import summarize_model


def make_row(variant, prediction, gold="A", relation="invariant"):
    return {
        "id": variant,
        "dataset": "x",
        "pair_key": "p",
        "audit_variant": variant,
        "expected_relation": relation,
        "gold_riskier_side": gold,
        "predicted_riskier_side": prediction,
        "supports_abstention": False,
        "text": "Unified diff from Side A to Side B:\n--- A\n+++ B\n-old\n+new\n",
        "runtime_accounting": {
            "critical_hunk_truncated": False,
            "transformation_introduced_critical_truncation": False,
            "token_count": 10,
        },
    }


def test_robust_accuracy_requires_correct_base_and_all_relations():
    rows = [
        make_row("canonical", "A"),
        make_row("side_swap", "B", gold="B", relation="equivariant_swap"),
        make_row("canonical_no_metadata", "A"),
        make_row("padding_pre_diff", "A"),
        make_row("padding_post_diff", "A"),
        make_row("padding_post_diff_terminal_phrase", "A"),
    ]
    report = summarize_model(rows, model_metadata={}, max_length=512)

    assert report["robust_accuracy"] == 1.0
    assert report["clean_robust_accuracy"] == 1.0

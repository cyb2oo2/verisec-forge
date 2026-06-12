from vrf.cross_model_relational_analysis import (
    compare_paired_models,
    summarize_model,
)


def make_row(variant, prediction, gold="A", relation="invariant"):
    return {
        "id": variant,
        "dataset": "x",
        "pair_key": "p",
        "audit_variant": variant,
        "expected_relation": relation,
        "gold_riskier_side": gold,
        "predicted_riskier_side": prediction,
        "confidence": 0.75,
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
        make_row("training_prompt", "A"),
        make_row(
            "training_prompt_side_swap",
            "B",
            gold="B",
            relation="equivariant_swap",
        ),
    ]
    report = summarize_model(rows, model_metadata={}, max_length=512)

    assert report["robust_accuracy"] == 1.0
    assert report["clean_pair_coverage"] == 1.0
    assert report["clean_robust_accuracy_conditional"] == 1.0
    assert report["clean_and_robust_coverage"] == 1.0


def test_paired_comparison_reports_endpoint_and_interaction_deltas():
    qwen = [
        {
            "dataset": "x",
            "pair_key": "p",
            "canonical_correct": True,
            "canonical_confidence": 0.7,
            "post_diff_relation": False,
            "terminal_phrase_relation": True,
            "training_contract_swap_relation": False,
            "all_visible": True,
        }
    ]
    codebert = [
        {
            "dataset": "x",
            "pair_key": "p",
            "canonical_correct": True,
            "canonical_confidence": 0.72,
            "post_diff_relation": True,
            "terminal_phrase_relation": True,
            "training_contract_swap_relation": True,
            "all_visible": True,
        }
    ]

    report = compare_paired_models(
        qwen, codebert, iterations=10, seed=1
    )
    all_pairs = report["subsets"]["all_pairs"]
    assert all_pairs["endpoint_gap_codebert_minus_qwen"]["estimate"] == 1.0
    assert all_pairs["terminal_recovery_interaction"]["estimate"] == 1.0

from vrf.cross_model_replication import (
    build_replication_report,
    markdown_report,
    pending_model,
    summarize_replication_model,
)
from scripts.run_generative_judge_replication import (
    convert_raw_generations,
    parse_label,
)


def runtime():
    return {
        "offset_mapping_quality": "exact_fast_tokenizer",
        "critical_hunk_truncated": False,
        "base_critical_hunk_truncated": False,
        "transformation_introduced_critical_truncation": False,
    }


def row(row_id, pair_key, relation, template, gold, base_id=None):
    return {
        "id": row_id,
        "base_id": base_id or row_id,
        "pair_key": pair_key,
        "cluster_id": f"demo::{pair_key}",
        "dataset": "demo",
        "sampling_suite": "representative",
        "expected_relation": relation,
        "transformation_template": template,
        "transformation_family": "test",
        "gold_riskier_side": gold,
        "runtime_accounting": runtime(),
    }


def prediction(row_id, label, *, supports_abstention=False):
    return {
        "id": row_id,
        "predicted_riskier_side": label,
        "supports_abstention": supports_abstention,
        "confidence": 0.9,
    }


def test_replication_summary_computes_swap_residual_and_suffix():
    benchmark = [
        row("p1:base", "p1", "identity", "canonical_pair_renderer_v2", "A"),
        row(
            "p1:swap",
            "p1",
            "equivariant_swap",
            "canonical_renderer_swap_v2",
            "B",
            base_id="p1:base",
        ),
        row(
            "p1:suffix",
            "p1",
            "invariant",
            "length_only_end_numbered_comments_v2",
            "A",
            base_id="p1:base",
        ),
    ]
    predictions = [
        prediction("p1:base", "A"),
        prediction("p1:swap", "B"),
        prediction("p1:suffix", "A"),
    ]

    summary = summarize_replication_model(
        benchmark,
        predictions,
        model_key="demo_decoder",
        model_type="decoder_sequence_classifier",
        model_id="demo",
        bootstrap_iterations=5,
    )

    assert summary["canonical_accuracy"] == 1.0
    assert summary["side_swap_equivariance"] == 1.0
    assert summary["side_swap_residual"] == 0.0
    assert summary["both_directions_correct"] == 1.0
    assert summary["suffix_consistency"] == 1.0
    assert summary["invalid_output_rate"] == 0.0


def test_generative_judge_parser_is_strict():
    assert parse_label("A_RISKIER") == "A_RISKIER"
    assert parse_label("final: B_RISKIER") == "INVALID"
    assert parse_label("A_RISKIER B_RISKIER") == "INVALID"
    assert parse_label("side A") == "INVALID"

    rows = convert_raw_generations(
        [
            {"id": "a", "generated_text": "INSUFFICIENT_CONTEXT"},
            {"id": "b", "generated_text": "explanation then A_RISKIER"},
        ]
    )
    assert rows[0]["predicted_riskier_side"] == "INSUFFICIENT_CONTEXT"
    assert rows[0]["supports_abstention"] is True
    assert rows[1]["predicted_riskier_side"] == "INVALID"


def test_pending_report_keeps_model_slots_visible():
    report = build_replication_report(
        [
            pending_model(
                model_key="non_qwen_decoder_classifier",
                model_type="decoder_sequence_classifier",
                interpretation="pending",
            )
        ]
    )
    markdown = markdown_report(report)

    assert report["status"] == "pending_predictions"
    assert "non_qwen_decoder_classifier" in markdown
    assert "new Qwen readout variants" in markdown

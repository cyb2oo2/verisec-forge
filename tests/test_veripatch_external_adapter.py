from pathlib import Path

import pytest

from vrf.external_adapter import (
    build_prediction_template,
    evaluate_external_predictions,
    validate_external_predictions,
)
from vrf.io_utils import read_jsonl


ROOT = Path(__file__).resolve().parents[1]


def tiny_runtime_row(row_id: str, *, relation: str, gold: str, base_id: str) -> dict:
    return {
        "id": row_id,
        "base_id": base_id,
        "pair_key": "pair-1",
        "cluster_id": "demo::pair-1",
        "dataset": "demo",
        "sampling_suite": "representative",
        "transformation_family": "base" if relation == "identity" else "test",
        "transformation_template": row_id,
        "expected_relation": relation,
        "gold_riskier_side": gold,
        "text": f"Prompt for {row_id}",
        "runtime_accounting": {
            "critical_hunk_truncated": False,
            "base_critical_hunk_truncated": False,
            "transformation_introduced_critical_truncation": False,
            "offset_mapping_quality": "exact_fast_tokenizer",
        },
    }


def test_external_prediction_template_preserves_ids_and_text() -> None:
    rows = [
        tiny_runtime_row("base", relation="identity", gold="A", base_id="base")
    ]

    template = build_prediction_template(rows)

    assert template == [
        {
            "id": "base",
            "text": "Prompt for base",
            "predicted_riskier_side": "",
            "probability_a": None,
            "supports_abstention": True,
        }
    ]


def test_external_validation_rejects_schema_problems() -> None:
    rows = [
        tiny_runtime_row("base", relation="identity", gold="A", base_id="base"),
        tiny_runtime_row("swap", relation="equivariant_swap", gold="B", base_id="base"),
    ]
    predictions = [
        {"id": "base", "predicted_riskier_side": "A"},
        {"id": "base", "predicted_riskier_side": "A"},
        {"id": "extra", "predicted_riskier_side": "SIDE_A"},
    ]

    report = validate_external_predictions(rows, predictions)

    assert report["status"] == "error"
    assert report["duplicate_ids"] == ["base"]
    assert report["missing_ids"] == ["swap"]
    assert report["extra_ids"] == ["extra"]
    assert report["invalid_labels"][0]["predicted_riskier_side"] == "SIDE_A"


def test_external_evaluation_uses_relational_metrics() -> None:
    rows = [
        tiny_runtime_row("base", relation="identity", gold="A", base_id="base"),
        tiny_runtime_row("swap", relation="equivariant_swap", gold="B", base_id="base"),
        tiny_runtime_row("suffix", relation="invariant", gold="A", base_id="base"),
    ]
    predictions = [
        {"id": "base", "predicted_riskier_side": "A", "probability_a": 0.9},
        {"id": "swap", "predicted_riskier_side": "B", "probability_a": 0.1},
        {"id": "suffix", "predicted_riskier_side": "A", "probability_a": 0.8},
    ]

    report = evaluate_external_predictions(rows, predictions, bootstrap_iterations=5)

    assert report["status"] == "ok"
    assert report["external_adapter"]["validation"]["status"] == "ok"
    assert "relational_claim_boundary" in report
    assert report["headline"]["relation_tests"]["robust_accuracy"] == 1.0


def test_checked_in_smoke_artifact_has_prediction_template() -> None:
    benchmark = read_jsonl(ROOT / "examples/veripatch_rr_smoke_30.jsonl")
    template = read_jsonl(
        ROOT / "examples/veripatch_rr_smoke_30_predictions_template.jsonl"
    )

    assert len({row["cluster_id"] for row in benchmark}) == 30
    assert len(benchmark) == 90
    assert [row["id"] for row in benchmark] == [row["id"] for row in template]
    assert {
        row["transformation_template"] for row in benchmark
    } == {
        "canonical_pair_renderer_v2",
        "canonical_renderer_swap_v2",
        "length_only_end_numbered_comments_v2",
    }

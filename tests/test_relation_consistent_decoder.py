from vrf.relation_consistent_decoder import (
    project_relation_consistent_predictions,
)


def row(row_id: str, relation: str, *, base_id: str = "base") -> dict:
    return {
        "id": row_id,
        "base_id": base_id,
        "expected_relation": relation,
        "pair_key": "pair-1",
        "dataset": "demo",
    }


def by_id(rows: list[dict]) -> dict[str, dict]:
    return {row["id"]: row for row in rows}


def test_relation_consistent_decoder_projects_swap_probabilities() -> None:
    benchmark = [
        row("base", "identity"),
        row("suffix", "invariant"),
        row("swap", "equivariant_swap"),
    ]
    predictions = [
        {"id": "base", "predicted_riskier_side": "A", "probability_a": 0.8},
        {"id": "suffix", "predicted_riskier_side": "A", "probability_a": 0.7},
        {"id": "swap", "predicted_riskier_side": "A", "probability_a": 0.7},
    ]

    result = project_relation_consistent_predictions(benchmark, predictions)
    projected = by_id(result["predictions"])

    assert projected["base"]["predicted_riskier_side"] == "A"
    assert projected["suffix"]["predicted_riskier_side"] == "A"
    assert projected["swap"]["predicted_riskier_side"] == "B"
    assert round(projected["base"]["probability_a"], 6) == 0.6
    assert round(projected["swap"]["probability_a"], 6) == 0.4
    assert result["summary"]["label_changes"] == 1
    assert "not a benchmark result" in result["summary"]["claim_boundary"]


def test_relation_consistent_decoder_does_not_use_gold_labels() -> None:
    benchmark = [
        {**row("base", "identity"), "gold_riskier_side": "B"},
        {**row("swap", "equivariant_swap"), "gold_riskier_side": "A"},
    ]
    predictions = [
        {"id": "base", "predicted_riskier_side": "A", "probability_a": 0.9},
        {"id": "swap", "predicted_riskier_side": "A", "probability_a": 0.8},
    ]

    result = project_relation_consistent_predictions(benchmark, predictions)
    projected = by_id(result["predictions"])

    assert projected["base"]["predicted_riskier_side"] == "A"
    assert projected["swap"]["predicted_riskier_side"] == "B"


def test_relation_consistent_decoder_skips_missing_probability_group() -> None:
    benchmark = [
        row("base", "identity"),
        row("swap", "equivariant_swap"),
    ]
    predictions = [
        {"id": "base", "predicted_riskier_side": "A", "probability_a": 0.9},
        {"id": "swap", "predicted_riskier_side": "B"},
    ]

    result = project_relation_consistent_predictions(benchmark, predictions)
    projected = by_id(result["predictions"])

    assert projected["base"]["predicted_riskier_side"] == "A"
    assert projected["swap"]["predicted_riskier_side"] == "B"
    assert result["summary"]["projected_rows"] == 0
    assert result["summary"]["skipped_reasons"] == {"missing_probability": 2}


def test_relation_consistent_decoder_preserves_context_pressure_and_abstention() -> None:
    benchmark = [
        row("base", "identity"),
        row("context", "context_pressure"),
        row("suffix", "invariant"),
    ]
    predictions = [
        {"id": "base", "predicted_riskier_side": "A", "probability_a": 0.9},
        {"id": "context", "predicted_riskier_side": "B", "probability_a": 0.1},
        {
            "id": "suffix",
            "predicted_riskier_side": "INSUFFICIENT_CONTEXT",
            "probability_a": 0.2,
        },
    ]

    result = project_relation_consistent_predictions(benchmark, predictions)
    projected = by_id(result["predictions"])

    assert projected["context"]["predicted_riskier_side"] == "B"
    assert projected["suffix"]["predicted_riskier_side"] == "INSUFFICIENT_CONTEXT"
    assert result["summary"]["skipped_reasons"] == {
        "abstention": 1,
        "unsupported_relation:context_pressure": 1,
    }


def test_relation_consistent_decoder_does_not_repair_invalid_labels() -> None:
    benchmark = [
        row("base", "identity"),
        row("swap", "equivariant_swap"),
    ]
    predictions = [
        {"id": "base", "predicted_riskier_side": "SIDE_A", "probability_a": 0.9},
        {"id": "swap", "predicted_riskier_side": "B", "probability_a": 0.1},
    ]

    result = project_relation_consistent_predictions(benchmark, predictions)
    projected = by_id(result["predictions"])

    assert projected["base"]["predicted_riskier_side"] == "SIDE_A"
    assert projected["swap"]["predicted_riskier_side"] == "B"
    assert result["summary"]["projected_rows"] == 1
    assert result["summary"]["skipped_reasons"] == {"invalid_label": 1}

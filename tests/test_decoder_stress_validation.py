import json
import subprocess
import sys
from pathlib import Path

from vrf.decoder_stress_validation import (
    run_decoder_stress_validation,
    shuffled_base_id_rows,
)
from vrf.relation_consistent_decoder import project_relation_consistent_predictions


ROOT = Path(__file__).resolve().parents[1]


RUNTIME = {
    "critical_hunk_truncated": False,
    "base_critical_hunk_truncated": False,
    "transformation_introduced_critical_truncation": False,
    "offset_mapping_quality": "exact_fast_tokenizer",
}


def row(row_id: str, relation: str, gold: str, *, base_id: str = "base") -> dict:
    return {
        "id": row_id,
        "base_id": base_id,
        "pair_key": base_id,
        "cluster_id": f"demo::{base_id}",
        "dataset": "demo",
        "sampling_suite": "representative",
        "transformation_family": "base" if relation == "identity" else "test",
        "transformation_template": row_id,
        "expected_relation": relation,
        "gold_riskier_side": gold,
        "text": row_id,
        "runtime_accounting": RUNTIME,
    }


def test_shuffled_base_id_rows_breaks_non_identity_pairing() -> None:
    rows = [
        row("base-1", "identity", "A", base_id="base-1"),
        row("swap-1", "equivariant_swap", "B", base_id="base-1"),
        row("base-2", "identity", "B", base_id="base-2"),
        row("swap-2", "equivariant_swap", "A", base_id="base-2"),
    ]

    shuffled = shuffled_base_id_rows(rows, seed=7)

    identity = [item for item in shuffled if item["expected_relation"] == "identity"]
    interventions = [
        item for item in shuffled if item["expected_relation"] != "identity"
    ]

    assert [item["base_id"] for item in identity] == ["base-1", "base-2"]
    assert {item["base_id"] for item in interventions} == {"base-1", "base-2"}
    assert any(
        original["base_id"] != changed["base_id"]
        for original, changed in zip(rows, shuffled)
        if original["expected_relation"] != "identity"
    )


def test_decoder_stress_validation_reports_structure_controls() -> None:
    benchmark = [
        row("base", "identity", "A"),
        row("suffix", "invariant", "A"),
        row("swap", "equivariant_swap", "B"),
    ]
    predictions = [
        {
            "id": "base",
            "predicted_riskier_side": "A",
            "probability_a": 0.8,
            "supports_abstention": False,
        },
        {
            "id": "suffix",
            "predicted_riskier_side": "A",
            "probability_a": 0.7,
            "supports_abstention": False,
        },
        {
            "id": "swap",
            "predicted_riskier_side": "A",
            "probability_a": 0.7,
            "supports_abstention": False,
        },
    ]

    report = run_decoder_stress_validation(
        benchmark, predictions, bootstrap_iterations=5
    )

    assert report["status"] == "ok"
    assert report["baseline"]["relation_success"] == 0.5
    assert report["decoded"]["relation_success"] == 1.0
    assert report["stress_metrics"]["relation_success_delta"] == 0.5
    assert report["stress_metrics"]["swap_consistency_gain"] == 1.0
    assert report["stress_metrics"]["identity_distortion_rate"] == 0.0
    assert report["stress_metrics"]["projected_row_coverage"] == 1.0
    assert "not a model quality claim" in report["claim_boundary"]


def test_decoder_stress_validation_tracks_invalid_and_abstention_preservation() -> None:
    benchmark = [
        row("base", "identity", "A"),
        row("suffix", "invariant", "A"),
        row("swap", "equivariant_swap", "B"),
    ]
    predictions = [
        {
            "id": "base",
            "predicted_riskier_side": "A",
            "probability_a": 0.8,
        },
        {
            "id": "suffix",
            "predicted_riskier_side": "INSUFFICIENT_CONTEXT",
            "probability_a": 0.7,
        },
        {
            "id": "swap",
            "predicted_riskier_side": "SIDE_A",
            "probability_a": 0.7,
        },
    ]

    report = project_relation_consistent_predictions(benchmark, predictions)

    assert report["summary"]["skipped_reasons"] == {
        "abstention": 1,
        "invalid_label": 1,
    }


def test_run_decoder_ablation_cli_writes_report(tmp_path: Path) -> None:
    benchmark = [
        row("base", "identity", "A"),
        row("suffix", "invariant", "A"),
        row("swap", "equivariant_swap", "B"),
    ]
    predictions = [
        {"id": "base", "predicted_riskier_side": "A", "probability_a": 0.8},
        {"id": "suffix", "predicted_riskier_side": "A", "probability_a": 0.7},
        {"id": "swap", "predicted_riskier_side": "A", "probability_a": 0.7},
    ]
    benchmark_path = tmp_path / "benchmark.jsonl"
    predictions_path = tmp_path / "predictions.jsonl"
    output_path = tmp_path / "report.json"
    benchmark_path.write_text(
        "\n".join(json.dumps(item) for item in benchmark) + "\n",
        encoding="utf-8",
    )
    predictions_path.write_text(
        "\n".join(json.dumps(item) for item in predictions) + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_decoder_ablation.py",
            "--benchmark",
            str(benchmark_path),
            "--predictions",
            str(predictions_path),
            "--output",
            str(output_path),
            "--bootstrap-iterations",
            "5",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["status"] == "ok"
    assert report["stress_metrics"]["relation_success_delta"] == 0.5

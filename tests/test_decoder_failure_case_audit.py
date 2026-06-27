import json
import subprocess
import sys
from pathlib import Path

from vrf.decoder_failure_audit import audit_decoder_identity_distortion


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports/decoder_failure_case_audit_v1.json"
MARKDOWN = ROOT / "reports/DECODER_FAILURE_CASE_AUDIT.md"


RUNTIME = {
    "critical_hunk_truncated": False,
    "base_critical_hunk_truncated": False,
    "transformation_introduced_critical_truncation": False,
    "offset_mapping_quality": "exact_fast_tokenizer",
}


def row(row_id: str, relation: str, gold: str, *, base_id: str) -> dict:
    return {
        "id": row_id,
        "base_id": base_id,
        "pair_key": base_id,
        "cluster_id": f"demo::{base_id}",
        "dataset": "demo",
        "project": "demo-project",
        "cwe": "cwe-demo",
        "cve": "CVE-DEMO",
        "sampling_suite": "representative",
        "transformation_family": "base" if relation == "identity" else "test",
        "transformation_template": row_id,
        "expected_relation": relation,
        "gold_riskier_side": gold,
        "text": row_id,
        "runtime_accounting": RUNTIME,
    }


def _fixture() -> tuple[list[dict], list[dict]]:
    benchmark = [
        row("base-cw", "identity", "A", base_id="case-cw"),
        row("inv-cw", "invariant", "A", base_id="case-cw"),
        row("swap-cw", "equivariant_swap", "B", base_id="case-cw"),
        row("base-wc", "identity", "A", base_id="case-wc"),
        row("inv-wc", "invariant", "A", base_id="case-wc"),
        row("swap-wc", "equivariant_swap", "B", base_id="case-wc"),
    ]
    predictions = [
        {"id": "base-cw", "predicted_riskier_side": "A", "probability_a": 0.8},
        {"id": "inv-cw", "predicted_riskier_side": "B", "probability_a": 0.1},
        {"id": "swap-cw", "predicted_riskier_side": "A", "probability_a": 0.9},
        {"id": "base-wc", "predicted_riskier_side": "B", "probability_a": 0.2},
        {"id": "inv-wc", "predicted_riskier_side": "A", "probability_a": 0.9},
        {"id": "swap-wc", "predicted_riskier_side": "B", "probability_a": 0.1},
    ]
    return benchmark, predictions


def test_decoder_failure_audit_counts_identity_distortions() -> None:
    benchmark, predictions = _fixture()

    report = audit_decoder_identity_distortion(
        benchmark, predictions, max_cases=None
    )

    assert report["status"] == "ok"
    assert report["summary"]["identity_rows"] == 2
    assert report["summary"]["distorted_identity_rows"] == 2
    assert report["summary"]["identity_distortion_rate"] == 1.0
    assert report["summary"]["flips_toward_gold"] == 1
    assert report["summary"]["flips_away_from_gold"] == 1
    assert report["summary"]["flip_outcome_counts"]["correct_to_wrong"] == 1
    assert report["summary"]["flip_outcome_counts"]["wrong_to_correct"] == 1
    assert report["summary"]["driver_counts"]

    case = report["distorted_identity_cases"][0]
    assert {
        "id",
        "pair_key",
        "dataset",
        "sampling_suite",
        "gold_riskier_side",
        "baseline_prediction",
        "decoded_prediction",
        "baseline_probability_a",
        "decoded_probability_a",
        "identity_margin",
        "canonical_projection_margin",
        "cross_view_probability_range",
        "view_contributors",
        "flip_outcome",
        "likely_driver",
    }.issubset(case)


def test_gold_labels_are_audit_only_not_projection_inputs() -> None:
    benchmark, predictions = _fixture()
    flipped_gold = [
        {**item, "gold_riskier_side": "B"}
        if item["expected_relation"] == "identity"
        else item
        for item in benchmark
    ]

    original = audit_decoder_identity_distortion(
        benchmark, predictions, max_cases=None
    )
    changed_gold = audit_decoder_identity_distortion(
        flipped_gold, predictions, max_cases=None
    )

    original_cases = {
        item["id"]: item for item in original["distorted_identity_cases"]
    }
    changed_cases = {
        item["id"]: item for item in changed_gold["distorted_identity_cases"]
    }

    for row_id, original_case in original_cases.items():
        changed_case = changed_cases[row_id]
        assert changed_case["decoded_probability_a"] == original_case[
            "decoded_probability_a"
        ]
        assert changed_case["decoded_prediction"] == original_case[
            "decoded_prediction"
        ]

    assert any(
        changed_cases[row_id]["flip_outcome"] != original_case["flip_outcome"]
        for row_id, original_case in original_cases.items()
    )
    assert "Gold labels are used only after the fact" in original["claim_boundary"]


def test_audit_decoder_failure_cases_cli_writes_artifacts(tmp_path: Path) -> None:
    benchmark, predictions = _fixture()
    benchmark_path = tmp_path / "benchmark.jsonl"
    predictions_path = tmp_path / "predictions.jsonl"
    output_json = tmp_path / "audit.json"
    output_md = tmp_path / "audit.md"
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
            "scripts/audit_decoder_failure_cases.py",
            "--benchmark",
            str(benchmark_path),
            "--predictions",
            str(predictions_path),
            "--output-json",
            str(output_json),
            "--output-md",
            str(output_md),
            "--max-cases",
            "10",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    report = json.loads(output_json.read_text(encoding="utf-8"))
    markdown = output_md.read_text(encoding="utf-8")
    assert report["summary"]["distorted_identity_rows"] == 2
    assert "Gold labels are used only to audit consequences" in markdown


def test_decoder_failure_audit_report_artifacts_exist() -> None:
    assert REPORT.exists()
    assert MARKDOWN.exists()
    assert REPORT.read_text(encoding="utf-8").strip()
    assert MARKDOWN.read_text(encoding="utf-8").strip()


def test_decoder_failure_audit_report_keeps_claim_boundary() -> None:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    markdown = MARKDOWN.read_text(encoding="utf-8")

    assert report["summary"]["identity_rows"] == 1200
    assert report["summary"]["distorted_identity_rows"] > 0
    assert "correct_to_wrong" in report["summary"]["flip_outcome_counts"]
    assert "wrong_to_correct" in report["summary"]["flip_outcome_counts"]
    assert "Gold labels are used only after the fact" in report["claim_boundary"]
    assert "does not claim improved model reasoning" in markdown
    assert "not as a standalone model quality result" in markdown

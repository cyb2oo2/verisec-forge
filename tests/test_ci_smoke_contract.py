from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from vrf.io_utils import read_jsonl, write_jsonl


ROOT = Path(__file__).resolve().parents[1]


def _run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def test_ci_external_adapter_cli_template_is_intentionally_unfilled(
    tmp_path: Path,
) -> None:
    template_path = tmp_path / "predictions_template.jsonl"
    invalid_report_path = tmp_path / "invalid_eval.json"

    template_run = _run_script(
        "scripts/evaluate_veripatch_external.py",
        "--benchmark",
        "examples/veripatch_rr_smoke_30.jsonl",
        "--write-template",
        str(template_path),
    )

    assert template_run.returncode == 0, template_run.stderr
    assert template_path.exists()

    eval_run = _run_script(
        "scripts/evaluate_veripatch_external.py",
        "--benchmark",
        "examples/veripatch_rr_smoke_30.jsonl",
        "--predictions",
        str(template_path),
        "--output",
        str(invalid_report_path),
    )

    assert eval_run.returncode == 2
    report = json.loads(invalid_report_path.read_text(encoding="utf-8"))
    assert report["status"] == "error"
    assert report["validation"]["status"] == "error"
    assert report["validation"]["invalid_labels"]


def test_ci_external_adapter_cli_evaluates_filled_smoke_predictions(
    tmp_path: Path,
) -> None:
    benchmark = read_jsonl(ROOT / "examples/veripatch_rr_smoke_30.jsonl")
    predictions_path = tmp_path / "filled_predictions.jsonl"
    output_path = tmp_path / "eval.json"
    write_jsonl(
        predictions_path,
        [
            {
                "id": row["id"],
                "predicted_riskier_side": "A",
                "supports_abstention": False,
            }
            for row in benchmark
        ],
    )

    eval_run = _run_script(
        "scripts/evaluate_veripatch_external.py",
        "--benchmark",
        "examples/veripatch_rr_smoke_30.jsonl",
        "--predictions",
        str(predictions_path),
        "--output",
        str(output_path),
        "--bootstrap-iterations",
        "10",
    )

    assert eval_run.returncode == 0, eval_run.stderr
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["status"] == "ok"
    assert report["external_adapter"]["validation"]["status"] == "ok"
    assert report["benchmark"] == "examples/veripatch_rr_smoke_30.jsonl"
    assert "relation_tests" in report["headline"]
    assert "relational_claim_boundary" in report


def test_ci_paper_anchor_map_and_boundary_doc_are_linked() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    results_index = (ROOT / "reports/RESULTS_INDEX.md").read_text(encoding="utf-8")
    ci_doc = (ROOT / "docs/CI_TESTING_STRATEGY.md").read_text(encoding="utf-8")

    assert "docs/CI_TESTING_STRATEGY.md" in readme
    assert "CI Testing Strategy" in results_index
    assert "does not train models" in ci_doc
    assert "does not convert the external smoke artifact into a benchmark result" in ci_doc
    assert "PrimeVul calibrated-router manifest" in ci_doc

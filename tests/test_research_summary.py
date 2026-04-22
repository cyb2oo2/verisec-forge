from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from vrf.research_summary import build_secure_code_research_summary, load_run_manifest


def test_research_summary_builds_from_manifest() -> None:
    tmp_path = Path(".tmp_test_runs") / f"summary-{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)
    reports_dir = tmp_path / "reports"
    analysis_dir = tmp_path / "analysis"
    reports_dir.mkdir()
    analysis_dir.mkdir()

    (reports_dir / "run_a.json").write_text(
        json.dumps(
            {
                "summary": {
                    "label_accuracy": 0.42,
                    "format_pass_rate": 0.9,
                    "invalid_output_rate": 0.1,
                    "high_confidence_error_rate": 0.03,
                    "avg_tokens": 12.0,
                }
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "run_a.json").write_text(
        json.dumps(
            {
                "label_error_breakdown": {"false_negative": 5},
                "format_error_breakdown": {"non_json_output": 2},
                "confidence_summary": {"0.75-0.89": {"accuracy": 0.8, "count": 10}},
            }
        ),
        encoding="utf-8",
    )
    (reports_dir / "run_b.json").write_text(
        json.dumps(
            {
                "summary": {
                    "label_accuracy": 0.55,
                    "format_pass_rate": 0.95,
                    "invalid_output_rate": 0.05,
                    "high_confidence_error_rate": 0.01,
                    "avg_tokens": 10.0,
                }
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "run_b.json").write_text(
        json.dumps(
            {
                "label_error_breakdown": {"false_positive": 3},
                "format_error_breakdown": {"missing_explanation_field": 1},
                "confidence_summary": {"0.9-1.0": {"accuracy": 0.9, "count": 12}},
            }
        ),
        encoding="utf-8",
    )

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "runs": [
                    {"name": "Run A", "report_path": "reports/run_a.json", "analysis_path": "analysis/run_a.json"},
                    {"name": "Run B", "report_path": "reports/run_b.json", "analysis_path": "analysis/run_b.json"},
                ]
            }
        ),
        encoding="utf-8",
    )

    run_specs = load_run_manifest(manifest_path, tmp_path)
    summary = build_secure_code_research_summary(run_specs)

    assert "| Run A | 0.4200 | 0.9000 | 0.1000 | 0.0300 | 12.0000 | false_negative | non_json_output |" in summary
    assert "| Run B | 0.5500 | 0.9500 | 0.0500 | 0.0100 | 10.0000 | false_positive | missing_explanation_field |" in summary
    assert "`Run B` is currently the strongest run by label accuracy (`0.5500`)." in summary
    assert "`Run B` has the lowest high-confidence error rate (`0.0100`) among the summarized runs." in summary
    assert "The most common dominant semantic error across the summarized runs is `false_negative`." in summary
    assert "The current best benchmark-facing checkpoint in this summary is `Run B`, based on `label_accuracy = 0.5500`." in summary

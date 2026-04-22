from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from vrf.run_specs import build_run_artifact_spec


def test_build_run_artifact_spec_derives_default_paths() -> None:
    spec = build_run_artifact_spec(
        dataset_path="data/processed/eval.jsonl",
        generations_path="outputs/run_generations.jsonl",
        report_json_path="reports/demo_report.json",
        tracker_path="artifacts/experiments.jsonl",
        metrics={"timeout_ms_threshold": 5000},
    )

    assert Path(spec.report_csv_path) == Path("reports") / "demo_report.csv"
    assert Path(spec.analysis_output_path) == Path("analysis") / "demo_failure_analysis.json"
    assert spec.evaluate_config()["tracker_path"] == "artifacts/experiments.jsonl"
    assert spec.evaluate_config()["metrics"]["timeout_ms_threshold"] == 5000
    assert Path(spec.analysis_config()["analysis_output_path"]) == Path("analysis") / "demo_failure_analysis.json"


def test_materialized_configs_round_trip() -> None:
    tmp_path = Path(".tmp_test_runs") / f"run-spec-{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    spec = build_run_artifact_spec(
        dataset_path="data/processed/eval.jsonl",
        generations_path="outputs/run_generations.jsonl",
        report_json_path=str(tmp_path / "reports" / "demo_report.json"),
    )

    eval_payload = spec.evaluate_config()
    analysis_payload = spec.analysis_config()

    assert Path(eval_payload["report_csv_path"]).name == "demo_report.csv"
    assert Path(analysis_payload["analysis_output_path"]).name == "demo_failure_analysis.json"
    json.dumps(eval_payload)
    json.dumps(analysis_payload)

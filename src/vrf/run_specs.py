from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class RunArtifactSpec:
    dataset_path: str
    generations_path: str
    report_json_path: str
    report_csv_path: str
    analysis_output_path: str
    tracker_path: str | None = None
    metrics: dict[str, Any] | None = None

    def evaluate_config(self) -> dict[str, Any]:
        payload = {
            "dataset_path": self.dataset_path,
            "generations_path": self.generations_path,
            "report_json_path": self.report_json_path,
            "report_csv_path": self.report_csv_path,
        }
        if self.tracker_path:
            payload["tracker_path"] = self.tracker_path
        if self.metrics is not None:
            payload["metrics"] = self.metrics
        return payload

    def analysis_config(self) -> dict[str, Any]:
        return {
            "dataset_path": self.dataset_path,
            "generations_path": self.generations_path,
            "analysis_output_path": self.analysis_output_path,
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_run_artifact_spec(
    *,
    dataset_path: str,
    generations_path: str,
    report_json_path: str,
    report_csv_path: str | None = None,
    analysis_output_path: str | None = None,
    tracker_path: str | None = None,
    metrics: dict[str, Any] | None = None,
) -> RunArtifactSpec:
    report_json = Path(report_json_path)
    if report_csv_path is None:
        report_csv_path = str(report_json.with_suffix(".csv"))
    if analysis_output_path is None:
        report_name = report_json.name
        analysis_name = report_name.replace("_report", "_failure_analysis")
        analysis_output_path = str(report_json.parent.parent / "analysis" / analysis_name)
    return RunArtifactSpec(
        dataset_path=dataset_path,
        generations_path=generations_path,
        report_json_path=report_json_path,
        report_csv_path=report_csv_path,
        analysis_output_path=analysis_output_path,
        tracker_path=tracker_path,
        metrics=metrics,
    )

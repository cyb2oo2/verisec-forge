from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from vrf.findings import (
    build_run_finding,
    derive_failure_taxonomy_findings,
    derive_key_findings,
    derive_practical_conclusions,
)


@dataclass(slots=True)
class ResearchRunSpec:
    name: str
    report_path: Path
    analysis_path: Path


def load_run_manifest(manifest_path: str | Path, root: str | Path | None = None) -> list[ResearchRunSpec]:
    manifest_file = Path(manifest_path)
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    base_root = Path(root) if root is not None else manifest_file.resolve().parents[2]
    runs: list[ResearchRunSpec] = []
    for item in manifest.get("runs", []):
        runs.append(
            ResearchRunSpec(
                name=item["name"],
                report_path=base_root / item["report_path"],
                analysis_path=base_root / item["analysis_path"],
            )
        )
    return runs


def _load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _fmt(value: float | int) -> str:
    if isinstance(value, int):
        return str(value)
    return f"{value:.4f}"


def _build_row(name: str, report: dict, analysis: dict) -> str:
    run = build_run_finding(name, report, analysis)
    summary = run.summary
    return (
        f"| {name} | {_fmt(summary['label_accuracy'])} | {_fmt(summary['format_pass_rate'])} | "
        f"{_fmt(summary['invalid_output_rate'])} | {_fmt(summary['high_confidence_error_rate'])} | "
        f"{_fmt(summary['avg_tokens'])} | {run.dominant_label_error} | {run.dominant_format_error} |"
    )


def build_secure_code_research_summary(run_specs: list[ResearchRunSpec]) -> str:
    lines = [
        "# Secure Code Research Summary",
        "",
        "This summary consolidates the current `PrimeVul eval244` secure-code reasoning results.",
        "",
        "| Model | Label Accuracy | Format Pass Rate | Invalid Output Rate | High-Confidence Error Rate | Avg Tokens | Dominant Label Error | Dominant Format Error |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]

    loaded_runs: list[tuple[str, dict, dict]] = []
    for run_spec in run_specs:
        if not run_spec.report_path.exists() or not run_spec.analysis_path.exists():
            continue
        report = _load_json(run_spec.report_path)
        analysis = _load_json(run_spec.analysis_path)
        loaded_runs.append((run_spec.name, report, analysis))
        lines.append(_build_row(run_spec.name, report, analysis))

    lines.extend(
        [
            "",
            "## Key Findings",
            "",
        ]
    )

    run_findings = [build_run_finding(name, report, analysis) for name, report, analysis in loaded_runs]

    for finding in derive_key_findings(run_findings):
        lines.append(f"- {finding}")

    lines.extend(
        [
            "",
            "## Research Readout",
            "",
        ]
    )

    for run in run_findings:
        summary = run.summary
        lines.append(
            f"- `{run.name}`: accuracy `{summary['label_accuracy']:.4f}`, format `{summary['format_pass_rate']:.4f}`, "
            f"invalid `{summary['invalid_output_rate']:.4f}`, dominant label error `{run.dominant_label_error}`, "
            f"dominant format error `{run.dominant_format_error}`, best confidence bucket `{run.best_confidence_bucket}`."
        )

    lines.extend(
        [
            "",
            "## Failure Taxonomy Readout",
            "",
        ]
    )
    for finding in derive_failure_taxonomy_findings(run_findings):
        lines.append(f"- {finding}")

    lines.extend(
        [
            "",
            "## Practical Conclusion",
            "",
        ]
    )
    for conclusion in derive_practical_conclusions(run_findings):
        lines.append(f"- {conclusion}")
    return "\n".join(lines) + "\n"

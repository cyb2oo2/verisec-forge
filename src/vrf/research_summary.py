from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


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


def _dominant(counter_like: dict[str, int]) -> str:
    if not counter_like:
        return "-"
    return max(counter_like.items(), key=lambda item: item[1])[0]


def _best_conf_bucket(confidence_summary: dict[str, dict]) -> str:
    if not confidence_summary:
        return "-"
    return max(
        confidence_summary.items(),
        key=lambda item: (item[1].get("accuracy", 0.0), item[1].get("count", 0)),
    )[0]


def _build_row(name: str, report: dict, analysis: dict) -> str:
    summary = report["summary"]
    label_breakdown = analysis.get("label_error_breakdown", {})
    dominant_label_error = _dominant(label_breakdown)
    format_breakdown = analysis.get("format_error_breakdown", {})
    dominant_format_error = _dominant(format_breakdown)
    return (
        f"| {name} | {_fmt(summary['label_accuracy'])} | {_fmt(summary['format_pass_rate'])} | "
        f"{_fmt(summary['invalid_output_rate'])} | {_fmt(summary['high_confidence_error_rate'])} | "
        f"{_fmt(summary['avg_tokens'])} | {dominant_label_error} | {dominant_format_error} |"
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
            "- `SFT 0.5B` remains the strongest overall model on the balanced secure-code benchmark.",
            "- `1.5B base` produces longer, more security-flavored analyses, but is badly over-calibrated and over-detects vulnerabilities.",
            "- Full-model DPO variants damage the output protocol more than they improve secure-code judgment.",
            "- LoRA-only DPO is safer than full-model DPO, but still has not surpassed the SFT anchor.",
            "",
            "## Research Readout",
            "",
        ]
    )

    best_name = None
    best_acc = -1.0
    for name, report, _analysis in loaded_runs:
        acc = report["summary"]["label_accuracy"]
        if acc > best_acc:
            best_acc = acc
            best_name = name

    if best_name:
        lines.append(f"- Best current model by label accuracy: `{best_name}` at `{best_acc:.4f}`.")

    for name, report, analysis in loaded_runs:
        summary = report["summary"]
        label_breakdown = analysis.get("label_error_breakdown", {})
        format_breakdown = analysis.get("format_error_breakdown", {})
        confidence_summary = analysis.get("confidence_summary", {})
        dominant_label_error = _dominant(label_breakdown)
        dominant_format_error = _dominant(format_breakdown)
        best_conf_bucket = _best_conf_bucket(confidence_summary)
        lines.append(
            f"- `{name}`: accuracy `{summary['label_accuracy']:.4f}`, format `{summary['format_pass_rate']:.4f}`, "
            f"invalid `{summary['invalid_output_rate']:.4f}`, dominant label error `{dominant_label_error}`, "
            f"dominant format error `{dominant_format_error}`, best confidence bucket `{best_conf_bucket}`."
        )

    lines.extend(
        [
            "",
            "## Failure Taxonomy Readout",
            "",
            "- `Base 0.5B` is mainly a false-negative model: it misses vulnerable code and is poorly calibrated when highly confident.",
            "- `SFT 0.5B` keeps the same dominant semantic error class (`false_negative`) but sharply reduces protocol breakage and high-confidence mistakes.",
            "- `Base 1.5B` is qualitatively different: its dominant failure is `false_positive`, which matches the observed over-detection bias.",
            "- The DPO variants split into two failure modes: full-model preference tuning collapses into `hard_fail` format errors, while LoRA-only DPO is structurally safer but still reintroduces more semantic errors than the SFT anchor.",
            "",
            "## Practical Conclusion",
            "",
            "- The strongest secure-code recipe in this repo is still `balanced PrimeVul + completion-only SFT + tolerant parser`.",
            "- The most trustworthy current model is not the one that sounds most security-fluent. `Base 1.5B` looks more expert but is much less calibrated than the `0.5B` SFT checkpoint.",
            "- The next research step should prioritize benchmark expansion, calibration analysis, and failure taxonomy over more aggressive preference tuning by default.",
        ]
    )
    return "\n".join(lines) + "\n"

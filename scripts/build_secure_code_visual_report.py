from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
ANALYSIS = ROOT / "analysis"


RUNS = {
    "eval244": {
        "Base 0.5B": (
            REPORTS / "secure_code_primevul_qwen05b_eval244_report.json",
            ANALYSIS / "secure_code_primevul_qwen05b_eval244_failure_analysis.json",
        ),
        "SFT 0.5B": (
            REPORTS / "secure_code_primevul_sft_qwen05b_balanced_lossfix_eval244_report.json",
            ANALYSIS / "secure_code_primevul_sft_qwen05b_balanced_lossfix_eval244_failure_analysis.json",
        ),
    },
    "holdout1000": {
        "Base 0.5B": (
            REPORTS / "secure_code_primevul_qwen05b_holdout1000_report.json",
            ANALYSIS / "secure_code_primevul_qwen05b_holdout1000_failure_analysis.json",
        ),
        "SFT 0.5B": (
            REPORTS / "secure_code_primevul_sft_qwen05b_balanced_lossfix_holdout1000_report.json",
            ANALYSIS / "secure_code_primevul_sft_qwen05b_balanced_lossfix_holdout1000_failure_analysis.json",
        ),
    },
}


def _load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _pct(part: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round(part / total, 4)


def _metric_chart(title: str, benchmark_name: str, metric_name: str, data: dict[str, tuple[dict, dict]]) -> str:
    labels = list(data.keys())
    values = [round(block[0]["summary"][metric_name], 4) for block in data.values()]
    quoted_labels = ", ".join(f'"{label}"' for label in labels)
    values_str = ", ".join(f"{value:.4f}" for value in values)
    return "\n".join(
        [
            "```mermaid",
            "xychart-beta",
            f'    title "{benchmark_name}: {title}"',
            '    x-axis ["Base 0.5B", "SFT 0.5B"]',
            '    y-axis "score" 0 --> 1',
            f"    bar [{values_str}]",
            "```",
        ]
    )


def _failure_chart(benchmark_name: str, model_name: str, analysis: dict) -> str:
    buckets = analysis.get("failure_buckets", {})
    total = sum(buckets.values())
    ordered = [
        ("correct", buckets.get("correct", 0)),
        ("label_failure", buckets.get("label_failure", 0)),
        ("format_failure", buckets.get("format_failure", 0)),
        ("high_confidence_error", buckets.get("high_confidence_error", 0)),
        ("evidence_failure", buckets.get("evidence_failure", 0)),
    ]
    body = "\n".join(f'    "{name}" : {count}' for name, count in ordered if count > 0)
    return "\n".join(
        [
            "```mermaid",
            "pie showData",
            f'    title "{benchmark_name}: {model_name} failure taxonomy (counts)"',
            body,
            "```",
        ]
    )


def _label_shape_chart(benchmark_name: str, model_name: str, analysis: dict) -> str:
    breakdown = analysis.get("label_error_breakdown", {})
    total = sum(breakdown.values())
    if total <= 0:
        return ""
    ordered = [
        ("false_negative", breakdown.get("false_negative", 0)),
        ("false_positive", breakdown.get("false_positive", 0)),
        ("cwe_mismatch", breakdown.get("cwe_mismatch", 0)),
        ("null_prediction", breakdown.get("null_prediction", 0)),
    ]
    body = "\n".join(f'    "{name}" : {count}' for name, count in ordered if count > 0)
    return "\n".join(
        [
            "```mermaid",
            "pie showData",
            f'    title "{benchmark_name}: {model_name} label error shape (counts)"',
            body,
            "```",
        ]
    )


def _calibration_chart(benchmark_name: str, model_name: str, analysis: dict) -> str:
    conf = analysis.get("confidence_summary", {})
    buckets = ["0.9-1.0", "0.75-0.89", "0.5-0.74", "0.0-0.49", "missing"]
    values = [round(conf.get(bucket, {}).get("accuracy", 0.0), 4) for bucket in buckets]
    values_str = ", ".join(f"{value:.4f}" for value in values)
    labels_str = ", ".join(f'"{bucket}"' for bucket in buckets)
    return "\n".join(
        [
            "```mermaid",
            "xychart-beta",
            f'    title "{benchmark_name}: {model_name} calibration by confidence bucket (accuracy)"',
            f"    x-axis [{labels_str}]",
            '    y-axis "accuracy" 0 --> 1',
            f"    bar [{values_str}]",
            "```",
        ]
    )


def _format_failure_table(analysis: dict) -> str:
    breakdown = analysis.get("format_error_breakdown", {})
    if not breakdown:
        return "| Format trigger | Count |\n| --- | ---: |\n| none | 0 |"
    lines = ["| Format trigger | Count |", "| --- | ---: |"]
    for key, value in sorted(breakdown.items(), key=lambda item: item[1], reverse=True):
        lines.append(f"| {key} | {value} |")
    return "\n".join(lines)


def main() -> None:
    loaded: dict[str, dict[str, tuple[dict, dict]]] = {}
    for benchmark_name, runs in RUNS.items():
        loaded[benchmark_name] = {}
        for model_name, (report_path, analysis_path) in runs.items():
            loaded[benchmark_name][model_name] = (_load_json(report_path), _load_json(analysis_path))

    lines: list[str] = [
        "# Secure Code Visual Diagnostics",
        "",
        "This report turns the current `PrimeVul` secure-code diagnostics into lightweight, dependency-free Mermaid charts.",
        "",
        "It is designed to answer two questions quickly:",
        "",
        "- where does `SFT` actually improve over `Base`?",
        "- how do error shape and calibration change when we move from `eval244` to `holdout1000`?",
        "",
        "## Benchmark-level Metric Comparison",
        "",
    ]

    for benchmark_name, run_data in loaded.items():
        lines.append(f"### {benchmark_name}")
        lines.append("")
        lines.append(_metric_chart("Label Accuracy", benchmark_name, "label_accuracy", run_data))
        lines.append("")
        lines.append(_metric_chart("Format Pass Rate", benchmark_name, "format_pass_rate", run_data))
        lines.append("")
        lines.append(_metric_chart("High-Confidence Error Rate", benchmark_name, "high_confidence_error_rate", run_data))
        lines.append("")

    lines.extend(["## Failure Taxonomy Visuals", ""])

    for benchmark_name, run_data in loaded.items():
        lines.append(f"### {benchmark_name}")
        lines.append("")
        for model_name, (_report, analysis) in run_data.items():
            lines.append(f"#### {model_name}")
            lines.append("")
            lines.append(_failure_chart(benchmark_name, model_name, analysis))
            lines.append("")
            label_chart = _label_shape_chart(benchmark_name, model_name, analysis)
            if label_chart:
                lines.append(label_chart)
                lines.append("")
            lines.append("Top format failure triggers:")
            lines.append("")
            lines.append(_format_failure_table(analysis))
            lines.append("")

    lines.extend(["## Calibration Visuals", ""])

    for benchmark_name, run_data in loaded.items():
        lines.append(f"### {benchmark_name}")
        lines.append("")
        for model_name, (_report, analysis) in run_data.items():
            lines.append(f"#### {model_name}")
            lines.append("")
            lines.append(_calibration_chart(benchmark_name, model_name, analysis))
            lines.append("")

    lines.extend(
        [
            "## Visual Readout",
            "",
            "- `SFT 0.5B` improves label accuracy on both benchmarks, but the bigger story is calibration: it removes most of the damaging high-confidence errors.",
            "- `holdout1000` is visibly harder than `eval244`, so the charts on the larger benchmark should be treated as the stronger estimate of real secure-code performance.",
            "- The remaining semantic error shape of the best model is still dominated by `false_negative`, which points future work toward recall and vulnerability coverage rather than more aggressive anti-overdetection tuning.",
        ]
    )

    output_path = REPORTS / "SECURE_CODE_VISUAL_DIAGNOSTICS.md"
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"output_path": str(output_path)}, indent=2))


if __name__ == "__main__":
    main()

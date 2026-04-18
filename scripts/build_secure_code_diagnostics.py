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


def _fmt(value: float) -> str:
    return f"{value:.4f}"


def _pct(part: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return part / total


def _failure_table(block: dict[str, tuple[dict, dict]]) -> list[str]:
    lines = [
        "| Model | Correct | Label Failure | Format Failure | High-Confidence Error | Evidence Failure |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for model_name, (_report, analysis) in block.items():
        buckets = analysis.get("failure_buckets", {})
        total = sum(buckets.values())
        lines.append(
            f"| {model_name} | "
            f"{_fmt(_pct(buckets.get('correct', 0), total))} | "
            f"{_fmt(_pct(buckets.get('label_failure', 0), total))} | "
            f"{_fmt(_pct(buckets.get('format_failure', 0), total))} | "
            f"{_fmt(_pct(buckets.get('high_confidence_error', 0), total))} | "
            f"{_fmt(_pct(buckets.get('evidence_failure', 0), total))} |"
        )
    return lines


def _label_breakdown_table(block: dict[str, tuple[dict, dict]]) -> list[str]:
    lines = [
        "| Model | False Negative | False Positive | CWE Mismatch | Null Prediction |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for model_name, (_report, analysis) in block.items():
        breakdown = analysis.get("label_error_breakdown", {})
        total = sum(breakdown.values())
        lines.append(
            f"| {model_name} | "
            f"{_fmt(_pct(breakdown.get('false_negative', 0), total))} | "
            f"{_fmt(_pct(breakdown.get('false_positive', 0), total))} | "
            f"{_fmt(_pct(breakdown.get('cwe_mismatch', 0), total))} | "
            f"{_fmt(_pct(breakdown.get('null_prediction', 0), total))} |"
        )
    return lines


def _calibration_table(block: dict[str, tuple[dict, dict]], model_name: str) -> list[str]:
    _report, analysis = block[model_name]
    conf = analysis.get("confidence_summary", {})
    lines = [
        f"### {model_name}",
        "",
        "| Confidence Bucket | Count | Accuracy | High-Confidence Error Rate |",
        "| --- | ---: | ---: | ---: |",
    ]
    for bucket in ["0.9-1.0", "0.75-0.89", "0.5-0.74", "0.0-0.49", "missing"]:
        if bucket not in conf:
            continue
        item = conf[bucket]
        lines.append(
            f"| {bucket} | {item.get('count', 0)} | {_fmt(item.get('accuracy', 0.0))} | "
            f"{_fmt(item.get('high_confidence_error_rate', 0.0))} |"
        )
    return lines


def _takeaways(eval244: dict[str, tuple[dict, dict]], holdout: dict[str, tuple[dict, dict]]) -> list[str]:
    _, eval_base_analysis = eval244["Base 0.5B"]
    _, eval_sft_analysis = eval244["SFT 0.5B"]
    _, holdout_base_analysis = holdout["Base 0.5B"]
    _, holdout_sft_analysis = holdout["SFT 0.5B"]

    eval_sft_fn = eval_sft_analysis.get("label_error_breakdown", {}).get("false_negative", 0)
    holdout_sft_fn = holdout_sft_analysis.get("label_error_breakdown", {}).get("false_negative", 0)
    holdout_base_fp = holdout_base_analysis.get("label_error_breakdown", {}).get("false_positive", 0)

    return [
        "## Diagnostic Takeaways",
        "",
        f"- On both benchmarks, the dominant semantic failure of the best current model (`SFT 0.5B`) is still `false_negative`. This shows the main remaining problem is missed vulnerabilities, not uncontrolled over-detection.",
        f"- The larger held-out benchmark exposes a more mixed base-model error shape: `Base 0.5B` shows substantial `false_negative` and `false_positive` mass, while `SFT 0.5B` collapses that pattern back toward mostly missed vulnerabilities.",
        "- Calibration is where SFT is most clearly better: on the larger held-out benchmark, the SFT checkpoint keeps most predictions in the `0.75-0.89` bucket with near-zero high-confidence error, while the base model's `0.9-1.0` bucket remains badly unreliable.",
        "- The small `eval244` slice is still useful for fast iteration, but `holdout1000` should now be treated as the stronger generalization check for claims about secure-code reliability.",
        f"- Concrete error counts reinforce that story: `SFT 0.5B` has `{eval_sft_fn}` false negatives on `eval244` and `{holdout_sft_fn}` false negatives on `holdout1000`, while `Base 0.5B` already accumulates `{holdout_base_fp}` false positives on the harder held-out benchmark.",
    ]


def main() -> None:
    loaded: dict[str, dict[str, tuple[dict, dict]]] = {}
    for benchmark_name, runs in RUNS.items():
        loaded[benchmark_name] = {}
        for model_name, (report_path, analysis_path) in runs.items():
            loaded[benchmark_name][model_name] = (_load_json(report_path), _load_json(analysis_path))

    lines: list[str] = [
        "# Secure Code Diagnostics",
        "",
        "This report focuses on the two most important diagnostic layers in the current `PrimeVul` experiments:",
        "",
        "- failure taxonomy shape",
        "- confidence and calibration behavior",
        "",
        "The goal is to show not just whether `SFT` beats `Base`, but *how* the error distribution changes across a small benchmark (`eval244`) and a larger held-out benchmark (`holdout1000`).",
        "",
        "## Failure Taxonomy Comparison",
        "",
        "### eval244",
        "",
    ]

    lines.extend(_failure_table(loaded["eval244"]))
    lines.extend(["", "### eval244 Label Error Shape", ""])
    lines.extend(_label_breakdown_table(loaded["eval244"]))
    lines.extend(["", "### holdout1000", ""])
    lines.extend(_failure_table(loaded["holdout1000"]))
    lines.extend(["", "### holdout1000 Label Error Shape", ""])
    lines.extend(_label_breakdown_table(loaded["holdout1000"]))

    lines.extend(["", "## Calibration Diagnostics", "", "### eval244", ""])
    lines.extend(_calibration_table(loaded["eval244"], "Base 0.5B"))
    lines.extend([""])
    lines.extend(_calibration_table(loaded["eval244"], "SFT 0.5B"))
    lines.extend(["", "### holdout1000", ""])
    lines.extend(_calibration_table(loaded["holdout1000"], "Base 0.5B"))
    lines.extend([""])
    lines.extend(_calibration_table(loaded["holdout1000"], "SFT 0.5B"))
    lines.extend([""])
    lines.extend(_takeaways(loaded["eval244"], loaded["holdout1000"]))

    output_path = REPORTS / "SECURE_CODE_DIAGNOSTICS.md"
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"output_path": str(output_path)}, indent=2))


if __name__ == "__main__":
    main()

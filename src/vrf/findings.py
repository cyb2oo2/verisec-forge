from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class DerivedRunFinding:
    name: str
    summary: dict[str, Any]
    dominant_label_error: str
    dominant_format_error: str
    best_confidence_bucket: str


def dominant(counter_like: dict[str, int]) -> str:
    if not counter_like:
        return "-"
    return max(counter_like.items(), key=lambda item: item[1])[0]


def best_confidence_bucket(confidence_summary: dict[str, dict[str, Any]]) -> str:
    if not confidence_summary:
        return "-"
    return max(
        confidence_summary.items(),
        key=lambda item: (item[1].get("accuracy", 0.0), item[1].get("count", 0)),
    )[0]


def build_run_finding(name: str, report: dict[str, Any], analysis: dict[str, Any]) -> DerivedRunFinding:
    return DerivedRunFinding(
        name=name,
        summary=report["summary"],
        dominant_label_error=dominant(analysis.get("label_error_breakdown", {})),
        dominant_format_error=dominant(analysis.get("format_error_breakdown", {})),
        best_confidence_bucket=best_confidence_bucket(analysis.get("confidence_summary", {})),
    )


def derive_key_findings(runs: list[DerivedRunFinding]) -> list[str]:
    if not runs:
        return ["No complete runs were available to derive findings."]

    label_winner = max(runs, key=lambda run: run.summary["label_accuracy"])
    format_winner = max(runs, key=lambda run: run.summary["format_pass_rate"])
    calibration_winner = min(runs, key=lambda run: run.summary["high_confidence_error_rate"])

    findings = [
        (
            f"`{label_winner.name}` is currently the strongest run by label accuracy "
            f"(`{label_winner.summary['label_accuracy']:.4f}`)."
        ),
        (
            f"`{format_winner.name}` is currently the most protocol-stable run by format pass rate "
            f"(`{format_winner.summary['format_pass_rate']:.4f}`)."
        ),
        (
            f"`{calibration_winner.name}` has the lowest high-confidence error rate "
            f"(`{calibration_winner.summary['high_confidence_error_rate']:.4f}`) among the summarized runs."
        ),
    ]

    sft_runs = [run for run in runs if "sft" in run.name.lower()]
    dpo_runs = [run for run in runs if "dpo" in run.name.lower()]
    base_runs = [run for run in runs if run.name.lower().startswith("base")]

    if sft_runs and dpo_runs:
        best_sft = max(sft_runs, key=lambda run: run.summary["label_accuracy"])
        best_dpo = max(dpo_runs, key=lambda run: run.summary["label_accuracy"])
        if best_dpo.summary["label_accuracy"] < best_sft.summary["label_accuracy"]:
            findings.append(
                f"DPO has not surpassed the best SFT anchor yet: `{best_sft.name}` "
                f"(`{best_sft.summary['label_accuracy']:.4f}`) still outperforms the strongest DPO run "
                f"`{best_dpo.name}` (`{best_dpo.summary['label_accuracy']:.4f}`)."
            )

    false_positive_outliers = [run for run in runs if run.dominant_label_error == "false_positive"]
    if false_positive_outliers:
        outlier = min(false_positive_outliers, key=lambda run: run.summary["label_accuracy"])
        findings.append(
            f"`{outlier.name}` is the clearest over-detection outlier in this slice: its dominant label error is "
            f"`false_positive`, and its label accuracy is `{outlier.summary['label_accuracy']:.4f}`."
        )

    if base_runs and sft_runs:
        best_base = max(base_runs, key=lambda run: run.summary["label_accuracy"])
        best_sft = max(sft_runs, key=lambda run: run.summary["label_accuracy"])
        if best_sft.summary["label_accuracy"] > best_base.summary["label_accuracy"]:
            findings.append(
                f"The strongest SFT run improves over the strongest base run by "
                f"`{best_sft.summary['label_accuracy'] - best_base.summary['label_accuracy']:.4f}` label-accuracy points."
            )

    return findings


def derive_failure_taxonomy_findings(runs: list[DerivedRunFinding]) -> list[str]:
    if not runs:
        return ["No failure-taxonomy findings were derived because no complete runs were available."]

    label_error_counts: dict[str, int] = {}
    format_error_counts: dict[str, int] = {}
    for run in runs:
        label_error_counts[run.dominant_label_error] = label_error_counts.get(run.dominant_label_error, 0) + 1
        format_error_counts[run.dominant_format_error] = format_error_counts.get(run.dominant_format_error, 0) + 1

    dominant_label = dominant(label_error_counts)
    dominant_format = dominant(format_error_counts)
    findings = [
        f"The most common dominant semantic error across the summarized runs is `{dominant_label}`.",
        f"The most common dominant protocol error across the summarized runs is `{dominant_format}`.",
    ]

    precision_oriented_runs = [
        run for run in runs if run.dominant_label_error == "false_negative" and run.summary["format_pass_rate"] >= 0.8
    ]
    if precision_oriented_runs:
        best_precision_oriented = max(precision_oriented_runs, key=lambda run: run.summary["label_accuracy"])
        findings.append(
            f"`{best_precision_oriented.name}` is the clearest example of the repo's current precision-oriented pattern: "
            f"it stays format-stable (`{best_precision_oriented.summary['format_pass_rate']:.4f}`) while remaining dominated by "
            f"`{best_precision_oriented.dominant_label_error}`."
        )

    return findings


def derive_practical_conclusions(runs: list[DerivedRunFinding]) -> list[str]:
    if not runs:
        return ["No practical conclusion could be derived because no runs were available."]

    label_winner = max(runs, key=lambda run: run.summary["label_accuracy"])
    format_winner = max(runs, key=lambda run: run.summary["format_pass_rate"])
    calibration_winner = min(runs, key=lambda run: run.summary["high_confidence_error_rate"])

    conclusions = [
        (
            f"The current best benchmark-facing checkpoint in this summary is `{label_winner.name}`, based on "
            f"`label_accuracy = {label_winner.summary['label_accuracy']:.4f}`."
        ),
        (
            f"If protocol stability is the priority, `{format_winner.name}` is the current strongest option with "
            f"`format_pass_rate = {format_winner.summary['format_pass_rate']:.4f}`."
        ),
        (
            f"If calibration risk is the priority, `{calibration_winner.name}` is the safest current choice in this slice "
            f"with `high_confidence_error_rate = {calibration_winner.summary['high_confidence_error_rate']:.4f}`."
        ),
    ]

    dominant_semantic_error = dominant(
        {run.dominant_label_error: sum(1 for other in runs if other.dominant_label_error == run.dominant_label_error) for run in runs}
    )
    conclusions.append(
        f"The main unresolved semantic problem across this run family is still `{dominant_semantic_error}`."
    )
    return conclusions

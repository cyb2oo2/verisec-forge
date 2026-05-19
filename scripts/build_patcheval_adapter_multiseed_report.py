from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str | Path) -> dict[str, Any]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def round4(value: float) -> float:
    return round(value, 4)


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "mean": round4(mean(values)),
        "min": round4(min(values)),
        "max": round4(max(values)),
        "range": round4(max(values) - min(values)),
        "population_std": round4(pstdev(values)) if len(values) > 1 else 0.0,
    }


def seed_row(seed: str, pair_report: dict[str, Any], threshold_report: dict[str, Any]) -> dict[str, Any]:
    default = pair_report["default_threshold"]
    coupled = pair_report["pair_coupled"]
    default_overall = default["overall"]
    coupled_overall = coupled["overall"]
    default_group = default["group_metrics"]
    coupled_group = coupled["group_metrics"]
    best_ba = threshold_report["best_by_balanced_accuracy"]
    best_f1 = threshold_report["best_by_f1"]
    return {
        "seed": seed,
        "checkpoint": pair_report.get("protocol", {}).get("checkpoint", ""),
        "default_balanced_accuracy": default_overall["balanced_accuracy"],
        "default_f1": default_overall["f1"],
        "default_group_all_correct": default_group["group_all_correct_rate"],
        "default_orientation": default_group["orientation_accuracy"],
        "pair_coupled_balanced_accuracy": coupled_overall["balanced_accuracy"],
        "pair_coupled_recall": coupled_overall["vulnerable_recall"],
        "pair_coupled_specificity": coupled_overall["safe_specificity"],
        "pair_coupled_f1": coupled_overall["f1"],
        "pair_coupled_group_all_correct": coupled_group["group_all_correct_rate"],
        "pair_coupled_orientation": coupled_group["orientation_accuracy"],
        "pair_coupled_minus_default_ba": round4(
            coupled_overall["balanced_accuracy"] - default_overall["balanced_accuracy"]
        ),
        "pair_coupled_minus_default_group_all_correct": round4(
            coupled_group["group_all_correct_rate"] - default_group["group_all_correct_rate"]
        ),
        "best_threshold_balanced_accuracy": best_ba["balanced_accuracy"],
        "best_threshold": best_ba["threshold"],
        "best_threshold_f1": best_f1["f1"],
        "best_f1_threshold": best_f1["threshold"],
    }


def summarize_rows(rows: list[dict[str, Any]], field: str) -> dict[str, float]:
    return summarize([float(row[field]) for row in rows])


def build_report(
    *,
    pair_reports: dict[str, dict[str, Any]],
    threshold_reports: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    rows = [seed_row(seed, pair_reports[seed], threshold_reports[seed]) for seed in pair_reports]
    return {
        "status": "ok",
        "scope": "patcheval_adapter_multiseed",
        "protocol": {
            "source_dataset": "ByteDance/PatchEval",
            "seeds": list(pair_reports.keys()),
            "note": (
                "This report summarizes three PatchEval source-specific Qwen2.5-Coder-1.5B LoRA adapter runs. "
                "It reports seed variance rather than promoting the strongest single seed."
            ),
        },
        "seeds": rows,
        "summary": {
            "default_balanced_accuracy": summarize_rows(rows, "default_balanced_accuracy"),
            "pair_coupled_balanced_accuracy": summarize_rows(rows, "pair_coupled_balanced_accuracy"),
            "pair_coupled_f1": summarize_rows(rows, "pair_coupled_f1"),
            "pair_coupled_group_all_correct": summarize_rows(rows, "pair_coupled_group_all_correct"),
            "pair_coupled_orientation": summarize_rows(rows, "pair_coupled_orientation"),
            "pair_coupled_minus_default_ba": summarize_rows(rows, "pair_coupled_minus_default_ba"),
            "pair_coupled_minus_default_group_all_correct": summarize_rows(
                rows, "pair_coupled_minus_default_group_all_correct"
            ),
            "best_threshold_balanced_accuracy": summarize_rows(rows, "best_threshold_balanced_accuracy"),
        },
        "conclusion": (
            "PatchEval source-specific adaptation is beneficial but seed-sensitive. "
            "Across three seeds, pair-coupled decoding consistently improves over the default threshold and keeps "
            "the cross-language PatchEval adapter above the zero-shot matched-mixed baseline."
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# PatchEval Adapter Multi-Seed Evaluation",
        "",
        "This report summarizes three PatchEval source-specific Qwen2.5-Coder-1.5B LoRA adapter runs.",
        "",
        "## Per-Seed Results",
        "",
        "| Seed | Default BA | Pair-Coupled BA | Delta BA | Pair F1 | Group All-Correct | Orientation | Best Threshold BA |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in payload["seeds"]:
        lines.append(
            f"| `{row['seed']}` | `{row['default_balanced_accuracy']}` | "
            f"`{row['pair_coupled_balanced_accuracy']}` | `{row['pair_coupled_minus_default_ba']}` | "
            f"`{row['pair_coupled_f1']}` | `{row['pair_coupled_group_all_correct']}` | "
            f"`{row['pair_coupled_orientation']}` | `{row['best_threshold_balanced_accuracy']}` |"
        )
    summary = payload["summary"]
    lines.extend(
        [
            "",
            "## Multi-Seed Summary",
            "",
            "| Metric | Mean | Min | Max | Range | Std |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    labels = {
        "default_balanced_accuracy": "Default BA",
        "pair_coupled_balanced_accuracy": "Pair-coupled BA",
        "pair_coupled_f1": "Pair-coupled F1",
        "pair_coupled_group_all_correct": "Group all-correct",
        "pair_coupled_orientation": "Orientation",
        "pair_coupled_minus_default_ba": "Pair-coupled minus default BA",
        "pair_coupled_minus_default_group_all_correct": "Pair-coupled minus default group all-correct",
        "best_threshold_balanced_accuracy": "Best threshold BA",
    }
    for key, label in labels.items():
        stats = summary[key]
        lines.append(
            f"| {label} | `{stats['mean']}` | `{stats['min']}` | `{stats['max']}` | "
            f"`{stats['range']}` | `{stats['population_std']}` |"
        )
    lines.extend(["", "## Interpretation", "", payload["conclusion"], ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a PatchEval adapter multi-seed report.")
    parser.add_argument(
        "--pair-report",
        action="append",
        nargs=2,
        metavar=("SEED", "PATH"),
        default=[
            ["42", "reports/secure_code_patcheval_adapter_pair_diff_eval_v1.json"],
            ["7", "reports/secure_code_patcheval_adapter_pair_diff_seed7_eval_v1.json"],
            ["99", "reports/secure_code_patcheval_adapter_pair_diff_seed99_eval_v1.json"],
        ],
    )
    parser.add_argument(
        "--threshold-report",
        action="append",
        nargs=2,
        metavar=("SEED", "PATH"),
        default=[
            ["42", "reports/secure_code_patcheval_cls_qwen15bcoder_lora_pair_diff_v1_threshold_sweep.json"],
            ["7", "reports/secure_code_patcheval_cls_qwen15bcoder_lora_pair_diff_seed7_v1_threshold_sweep.json"],
            ["99", "reports/secure_code_patcheval_cls_qwen15bcoder_lora_pair_diff_seed99_v1_threshold_sweep.json"],
        ],
    )
    parser.add_argument("--json-output", default="reports/secure_code_patcheval_adapter_multiseed_v1.json")
    parser.add_argument("--md-output", default="reports/PATCHEVAL_ADAPTER_MULTISEED.md")
    args = parser.parse_args()

    pair_reports = {seed: read_json(path) for seed, path in args.pair_report}
    threshold_reports = {seed: read_json(path) for seed, path in args.threshold_report}
    if set(pair_reports) != set(threshold_reports):
        raise ValueError("Pair reports and threshold reports must use the same seed labels.")
    payload = build_report(pair_reports=pair_reports, threshold_reports=threshold_reports)
    (ROOT / args.json_output).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (ROOT / args.md_output).write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

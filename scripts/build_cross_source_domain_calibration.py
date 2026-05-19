from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str | Path) -> dict[str, Any]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def counts_to_metrics(counts: dict[str, int]) -> dict[str, Any]:
    tp = int(counts.get("tp", 0))
    tn = int(counts.get("tn", 0))
    fp = int(counts.get("fp", 0))
    fn = int(counts.get("fn", 0))
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "num_examples": total,
        "presence_accuracy": round(accuracy, 4),
        "balanced_accuracy": round((recall + specificity) / 2, 4),
        "vulnerable_recall": round(recall, 4),
        "safe_specificity": round(specificity, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def add_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    for row in rows:
        for key in counts:
            counts[key] += int(row.get(key, 0))
    return counts


def threshold_index(report: dict[str, Any]) -> dict[float, dict[str, Any]]:
    return {float(row["threshold"]): row for row in report["thresholds"]}


def build_report(
    *,
    prime_threshold_report: dict[str, Any],
    delta_threshold_report: dict[str, Any],
    prime_pair_report: dict[str, Any],
    delta_pair_report: dict[str, Any],
) -> dict[str, Any]:
    prime_by_threshold = threshold_index(prime_threshold_report)
    delta_by_threshold = threshold_index(delta_threshold_report)
    shared_thresholds = sorted(set(prime_by_threshold) & set(delta_by_threshold))

    global_rows: list[dict[str, Any]] = []
    for threshold in shared_thresholds:
        prime_row = prime_by_threshold[threshold]
        delta_row = delta_by_threshold[threshold]
        metrics = counts_to_metrics(add_counts([prime_row, delta_row]))
        global_rows.append(
            {
                "threshold": threshold,
                "global": metrics,
                "primevul_time": {
                    key: prime_row[key]
                    for key in [
                        "balanced_accuracy",
                        "vulnerable_recall",
                        "safe_specificity",
                        "precision",
                        "f1",
                        "tp",
                        "tn",
                        "fp",
                        "fn",
                    ]
                },
                "deltasecommits": {
                    key: delta_row[key]
                    for key in [
                        "balanced_accuracy",
                        "vulnerable_recall",
                        "safe_specificity",
                        "precision",
                        "f1",
                        "tp",
                        "tn",
                        "fp",
                        "fn",
                    ]
                },
            }
        )

    best_global = max(global_rows, key=lambda row: (row["global"]["balanced_accuracy"], row["global"]["f1"]))
    prime_best = prime_threshold_report["best_by_balanced_accuracy"]
    delta_best = delta_threshold_report["best_by_balanced_accuracy"]
    source_aware_metrics = counts_to_metrics(add_counts([prime_best, delta_best]))
    source_aware = {
        "global": source_aware_metrics,
        "primevul_time_threshold": prime_best["threshold"],
        "deltasecommits_threshold": delta_best["threshold"],
        "primevul_time": prime_best,
        "deltasecommits": delta_best,
    }
    pair_coupled = {
        "primevul_time": {
            "balanced_accuracy": prime_pair_report["pair_coupled"]["overall"]["balanced_accuracy"],
            "group_all_correct": prime_pair_report["pair_coupled"]["group_metrics"]["group_all_correct_rate"],
            "orientation_accuracy": prime_pair_report["pair_coupled"]["group_metrics"]["orientation_accuracy"],
        },
        "deltasecommits": {
            "balanced_accuracy": delta_pair_report["pair_coupled"]["overall"]["balanced_accuracy"],
            "group_all_correct": delta_pair_report["pair_coupled"]["group_metrics"]["group_all_correct_rate"],
            "orientation_accuracy": delta_pair_report["pair_coupled"]["group_metrics"]["orientation_accuracy"],
        },
    }
    return {
        "status": "ok",
        "scope": "matched_mixed_cross_source_domain_calibration",
        "system": "PrimeVul-short+Delta matched",
        "sources": ["primevul_time_ge2021", "deltasecommits_cpp_eval"],
        "global_threshold_sweep": global_rows,
        "best_global_threshold": best_global,
        "source_aware_thresholds": source_aware,
        "source_aware_minus_best_global": {
            "balanced_accuracy": round(
                source_aware_metrics["balanced_accuracy"] - best_global["global"]["balanced_accuracy"], 4
            ),
            "f1": round(source_aware_metrics["f1"] - best_global["global"]["f1"], 4),
        },
        "pair_coupled": pair_coupled,
        "conclusion": (
            "The matched mixed-source checkpoint has different best thresholds on PrimeVul-time and DeltaSecommits. "
            "However, source-aware thresholding does not materially improve over the best shared threshold on the combined eval; the remaining cross-source gap is in pair-coupled consistency, not just scalar threshold calibration."
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    best = payload["best_global_threshold"]
    aware = payload["source_aware_thresholds"]
    pair = payload["pair_coupled"]
    lines = [
        "# Cross-Source Domain Calibration",
        "",
        "This report evaluates whether the matched mixed-source checkpoint should use one global threshold or source-aware thresholds across PrimeVul-time and DeltaSecommits.",
        "",
        "## Summary",
        "",
        f"- Best shared threshold: `{best['threshold']}` with global BA `{best['global']['balanced_accuracy']}` and F1 `{best['global']['f1']}`.",
        f"- Source-aware thresholds: PrimeVul-time `{aware['primevul_time_threshold']}`, DeltaSecommits `{aware['deltasecommits_threshold']}`.",
        f"- Source-aware global BA/F1: `{aware['global']['balanced_accuracy']}` / `{aware['global']['f1']}`.",
        f"- Source-aware minus best shared BA/F1: `{payload['source_aware_minus_best_global']['balanced_accuracy']}` / `{payload['source_aware_minus_best_global']['f1']}`.",
        "",
        "## Shared Threshold Sweep",
        "",
        "| Threshold | Global BA | PrimeVul BA | Delta BA | Global F1 |",
        "| ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in payload["global_threshold_sweep"]:
        lines.append(
            f"| `{row['threshold']}` | `{row['global']['balanced_accuracy']}` | "
            f"`{row['primevul_time']['balanced_accuracy']}` | `{row['deltasecommits']['balanced_accuracy']}` | "
            f"`{row['global']['f1']}` |"
        )
    lines.extend(
        [
            "",
            "## Pair-Coupled Snapshot",
            "",
            "| Source | Pair-Coupled BA | Group All-Correct | Orientation |",
            "| --- | ---: | ---: | ---: |",
            f"| `PrimeVul-time` | `{pair['primevul_time']['balanced_accuracy']}` | `{pair['primevul_time']['group_all_correct']}` | `{pair['primevul_time']['orientation_accuracy']}` |",
            f"| `DeltaSecommits` | `{pair['deltasecommits']['balanced_accuracy']}` | `{pair['deltasecommits']['group_all_correct']}` | `{pair['deltasecommits']['orientation_accuracy']}` |",
            "",
            "## Interpretation",
            "",
            payload["conclusion"],
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build cross-source calibration report for matched mixed-source checkpoint.")
    parser.add_argument(
        "--prime-threshold-report",
        default="reports/secure_code_matched_mixed_primevul_time_short_deltasecommits_cls_qwen15bcoder_lora_pair_diff_v1_primevul_time_threshold_sweep.json",
    )
    parser.add_argument(
        "--delta-threshold-report",
        default="reports/secure_code_matched_mixed_primevul_time_short_deltasecommits_cls_qwen15bcoder_lora_pair_diff_v1_delta_threshold_sweep.json",
    )
    parser.add_argument(
        "--prime-pair-report",
        default="reports/secure_code_primevul_time_disjoint_matched_mixed_primevul_short_delta_v1.json",
    )
    parser.add_argument(
        "--delta-pair-report",
        default="reports/secure_code_deltasecommits_matched_mixed_primevul_time_short_delta_pair_diff_eval_v1.json",
    )
    parser.add_argument("--json-output", default="reports/secure_code_cross_source_domain_calibration_v1.json")
    parser.add_argument("--md-output", default="reports/CROSS_SOURCE_DOMAIN_CALIBRATION.md")
    args = parser.parse_args()

    payload = build_report(
        prime_threshold_report=read_json(args.prime_threshold_report),
        delta_threshold_report=read_json(args.delta_threshold_report),
        prime_pair_report=read_json(args.prime_pair_report),
        delta_pair_report=read_json(args.delta_pair_report),
    )
    (ROOT / args.json_output).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (ROOT / args.md_output).write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.evaluate_primevul_bucket_router import compute_binary_metrics, compute_group_metrics
from scripts.evaluate_primevul_pair_coupled_router import apply_pair_coupling
from vrf.io_utils import ensure_parent, read_json, read_jsonl, write_json, write_jsonl


def _bucket_from_pair_text(row: dict[str, Any]) -> str:
    diff = str(row.get("pair_text") or "")
    changed = sum(1 for line in diff.splitlines() if line.startswith(("+", "-")) and not line.startswith(("+++", "---")))
    if changed <= 2:
        return "00-02"
    if changed <= 5:
        return "03-05"
    if changed <= 10:
        return "06-10"
    if changed <= 25:
        return "11-25"
    return "26+"


def join_predictions(metadata_rows: list[dict[str, Any]], predictions: list[dict[str, Any]], *, threshold: float) -> list[dict[str, Any]]:
    metadata_by_id = {row["id"]: row for row in metadata_rows}
    rows: list[dict[str, Any]] = []
    for prediction in predictions:
        metadata = metadata_by_id.get(prediction["id"])
        if not metadata:
            continue
        probability = float(prediction["vuln_probability"])
        rows.append(
            {
                **prediction,
                "pred": int(probability >= threshold),
                "pair_key": metadata.get("pair_key"),
                "project": metadata.get("project"),
                "cve": metadata.get("cve"),
                "cve_year": metadata.get("cve_year"),
                "vulnerability_type": metadata.get("vulnerability_type"),
                "changed_line_bucket": metadata.get("changed_line_bucket") or _bucket_from_pair_text(metadata),
            }
        )
    return rows


def build_report(
    metadata_rows: list[dict[str, Any]],
    predictions: list[dict[str, Any]],
    *,
    default_threshold_report: dict[str, Any],
    selected_threshold_report: dict[str, Any],
    threshold: float,
    margin: float,
    scope: str = "primevul_time_disjoint_transfer",
    checkpoint_label: str = "cls_secure_code_primevul_qwen15bcoder_lora_pair_diff_only_3000_v1",
    protocol_note: str = "This report evaluates the original paired-diff detector checkpoint on the true CVE-year time-disjoint eval split. No retraining is performed here; this is a temporal transfer baseline.",
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    threshold_rows = join_predictions(metadata_rows, predictions, threshold=threshold)
    pair_rows, coupling_counts = apply_pair_coupling(threshold_rows, margin=margin)
    report = {
        "status": "ok",
        "scope": scope,
        "protocol": {
            "checkpoint": checkpoint_label,
            "note": protocol_note,
            "threshold": threshold,
            "pair_coupling_margin": margin,
        },
        "split": {
            "rows": len(threshold_rows),
            "unique_pair_count": len({str(row.get("pair_key") or row["id"]) for row in threshold_rows}),
            "cve_years": sorted({int(row["cve_year"]) for row in threshold_rows if row.get("cve_year") is not None}),
        },
        "default_threshold": default_threshold_report,
        "selected_threshold": selected_threshold_report,
        "pair_coupled": {
            "overall": compute_binary_metrics(pair_rows),
            "group_metrics": compute_group_metrics(pair_rows),
            "coupling_counts": coupling_counts,
        },
    }
    report["delta_vs_selected_threshold"] = {
        "balanced_accuracy": round(
            report["pair_coupled"]["overall"]["balanced_accuracy"]
            - float(selected_threshold_report["balanced_accuracy"]),
            4,
        ),
        "group_all_correct_rate": round(
            report["pair_coupled"]["group_metrics"]["group_all_correct_rate"]
            - compute_group_metrics(threshold_rows)["group_all_correct_rate"],
            4,
        ),
        "orientation_accuracy": round(
            report["pair_coupled"]["group_metrics"]["orientation_accuracy"]
            - compute_group_metrics(threshold_rows)["orientation_accuracy"],
            4,
        ),
    }
    return report, pair_rows


def render_report(report: dict[str, Any]) -> str:
    default = report["default_threshold"]
    selected = report["selected_threshold"]
    pair = report["pair_coupled"]
    delta = report["delta_vs_selected_threshold"]
    title = "PrimeVul Time-Disjoint Transfer Evaluation"
    if "direct" in str(report.get("scope", "")):
        title = "PrimeVul Time-Disjoint Direct-Train Evaluation"
    return "\n".join(
        [
            f"# {title}",
            "",
            str(report["protocol"]["note"]),
            "",
            "## Split",
            "",
            f"- Rows: `{report['split']['rows']}`",
            f"- Unique pair groups: `{report['split']['unique_pair_count']}`",
            f"- CVE years: `{report['split']['cve_years']}`",
            "",
            "## Results",
            "",
            "| System | Threshold | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            _row("default threshold", default, "0.5", None),
            _row("selected threshold", selected, str(selected["threshold"]), None),
            _row("pair-coupled", pair["overall"], str(report["protocol"]["threshold"]), pair["group_metrics"]),
            "",
            "## Delta",
            "",
            f"- Pair-coupled minus selected-threshold BA: `{delta['balanced_accuracy']}`",
            f"- Pair-coupled minus selected-threshold group all-correct: `{delta['group_all_correct_rate']}`",
            f"- Pair-coupled minus selected-threshold orientation: `{delta['orientation_accuracy']}`",
            "",
            "## Interpretation",
            "",
            "This report uses the true CVE-year time-disjoint eval split. The selected threshold is chosen from the supplied threshold sweep, and pair-coupled decoding is evaluated as a structured inference layer over paired vulnerable/fixed groups.",
            "",
        ]
    )


def _row(name: str, overall: dict[str, Any], threshold: str, group: dict[str, Any] | None) -> str:
    group_all = "" if group is None else str(group["group_all_correct_rate"])
    orientation = "" if group is None else str(group["orientation_accuracy"])
    balanced_accuracy = overall.get("balanced_accuracy", overall.get("presence_accuracy", ""))
    return (
        f"| `{name}` | `{threshold}` | `{balanced_accuracy}` | `{overall['vulnerable_recall']}` | "
        f"`{overall['safe_specificity']}` | `{overall['precision']}` | `{overall['f1']}` | "
        f"`{group_all}` | `{orientation}` |"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate original paired-diff checkpoint transfer to PrimeVul time-disjoint eval.")
    parser.add_argument("--metadata", default="data/processed/secure_code_primevul_pair_diff_time_eval_ge2021_balanced_2000_metadata.jsonl")
    parser.add_argument("--predictions", default="outputs/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_time_eval_ge2021_predictions.jsonl")
    parser.add_argument("--threshold-sweep", default="reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_time_eval_ge2021_threshold_sweep.json")
    parser.add_argument("--default-report", default="reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_time_eval_ge2021_report.json")
    parser.add_argument("--pair-margin", type=float, default=0.02)
    parser.add_argument("--scope", default="primevul_time_disjoint_transfer")
    parser.add_argument("--checkpoint-label", default="cls_secure_code_primevul_qwen15bcoder_lora_pair_diff_only_3000_v1")
    parser.add_argument(
        "--protocol-note",
        default="This report evaluates the original paired-diff detector checkpoint on the true CVE-year time-disjoint eval split. No retraining is performed here; this is a temporal transfer baseline.",
    )
    parser.add_argument("--json-output", default="reports/secure_code_primevul_time_disjoint_transfer_v1.json")
    parser.add_argument("--md-output", default="reports/PRIMEVUL_TIME_DISJOINT_TRANSFER.md")
    parser.add_argument("--predictions-output", default="outputs/secure_code_primevul_time_disjoint_pair_coupled_transfer_v1_predictions.jsonl")
    args = parser.parse_args()

    sweep = read_json(ROOT / args.threshold_sweep)
    selected = sweep["best_by_balanced_accuracy"]
    report, pair_rows = build_report(
        read_jsonl(ROOT / args.metadata),
        read_jsonl(ROOT / args.predictions),
        default_threshold_report=read_json(ROOT / args.default_report),
        selected_threshold_report=selected,
        threshold=float(selected["threshold"]),
        margin=args.pair_margin,
        scope=args.scope,
        checkpoint_label=args.checkpoint_label,
        protocol_note=args.protocol_note,
    )
    write_json(ROOT / args.json_output, report)
    write_jsonl(ROOT / args.predictions_output, pair_rows)
    md_path = ensure_parent(ROOT / args.md_output)
    md_path.write_text(render_report(report), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

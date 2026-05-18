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
from vrf.io_utils import ensure_parent, read_jsonl, write_json, write_jsonl


def _join_predictions(metadata_rows: list[dict[str, Any]], prediction_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metadata_by_id = {row["id"]: row for row in metadata_rows}
    rows: list[dict[str, Any]] = []
    for pred in prediction_rows:
        meta = metadata_by_id.get(pred["id"])
        if not meta:
            continue
        rows.append(
            {
                **pred,
                "pair_key": meta.get("pair_key"),
                "cve": meta.get("cve"),
                "project": meta.get("project"),
                "changed_line_bucket": meta.get("changed_line_bucket") or _bucket_from_pair_text(meta),
                "has_vulnerability": meta.get("has_vulnerability"),
            }
        )
    return rows


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


def _filter_cve_disjoint(
    train_rows: list[dict[str, Any]],
    eval_rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    train_cves = {str(row.get("cve")) for row in train_rows if row.get("cve")}
    kept = [row for row in eval_rows if str(row.get("cve")) not in train_cves]
    removed = [row for row in eval_rows if str(row.get("cve")) in train_cves]
    return kept, {
        "train_unique_cves": len(train_cves),
        "eval_rows_before": len(eval_rows),
        "eval_rows_after": len(kept),
        "removed_rows": len(removed),
        "removed_unique_cves": len({str(row.get("cve")) for row in removed if row.get("cve")}),
        "cve_overlap_after_filter": len(train_cves & {str(row.get("cve")) for row in kept if row.get("cve")}),
    }


def build_report(
    train_metadata: list[dict[str, Any]],
    eval_metadata: list[dict[str, Any]],
    predictions: list[dict[str, Any]],
    *,
    margin: float,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    joined_rows = _join_predictions(eval_metadata, predictions)
    cve_rows, split = _filter_cve_disjoint(train_metadata, joined_rows)
    pair_rows, coupling_counts = apply_pair_coupling(cve_rows, margin=margin)
    report = {
        "status": "ok",
        "scope": "primevul_cve_disjoint_eval",
        "protocol": {
            "train_cves_removed_from_eval": True,
            "source_eval": "pair_diff_only_eval_balanced_1800_dedup",
            "model": "qwen15bcoder_lora_pair_diff_only_3000_v1",
            "pair_coupling_margin": margin,
        },
        "split": split,
        "baseline": {
            "overall": compute_binary_metrics(cve_rows),
            "group_metrics": compute_group_metrics(cve_rows),
        },
        "pair_coupled": {
            "overall": compute_binary_metrics(pair_rows),
            "group_metrics": compute_group_metrics(pair_rows),
            "coupling_counts": coupling_counts,
        },
    }
    report["delta"] = {
        "balanced_accuracy": round(
            report["pair_coupled"]["overall"]["balanced_accuracy"]
            - report["baseline"]["overall"]["balanced_accuracy"],
            4,
        ),
        "group_all_correct_rate": round(
            report["pair_coupled"]["group_metrics"]["group_all_correct_rate"]
            - report["baseline"]["group_metrics"]["group_all_correct_rate"],
            4,
        ),
        "orientation_accuracy": round(
            report["pair_coupled"]["group_metrics"]["orientation_accuracy"]
            - report["baseline"]["group_metrics"]["orientation_accuracy"],
            4,
        ),
    }
    return report, pair_rows


def render_report(report: dict[str, Any]) -> str:
    baseline = report["baseline"]
    pair = report["pair_coupled"]
    return "\n".join(
        [
            "# PrimeVul CVE-Disjoint Evaluation",
            "",
            "This stress evaluation removes every eval row whose CVE appears in the paired-diff training metadata.",
            "It is an external-generalization check over unseen CVE identifiers, not a newly trained model.",
            "",
            "## Split",
            "",
            f"- Train unique CVEs: `{report['split']['train_unique_cves']}`",
            f"- Eval rows before filter: `{report['split']['eval_rows_before']}`",
            f"- Eval rows after filter: `{report['split']['eval_rows_after']}`",
            f"- Removed overlap rows: `{report['split']['removed_rows']}`",
            f"- CVE overlap after filter: `{report['split']['cve_overlap_after_filter']}`",
            "",
            "## Results",
            "",
            "| System | Balanced Accuracy | Recall | Specificity | F1 | Group All-Correct | Orientation |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
            _row("diff_only", baseline),
            _row("pair_coupled", pair),
            "",
            "## Delta",
            "",
            f"- Pair-coupled minus diff-only balanced accuracy: `{report['delta']['balanced_accuracy']}`",
            f"- Pair-coupled minus diff-only group all-correct: `{report['delta']['group_all_correct_rate']}`",
            f"- Pair-coupled minus diff-only orientation accuracy: `{report['delta']['orientation_accuracy']}`",
            "",
            "## Interpretation",
            "",
            "If this remains close to the normal paired-diff result, the mainline is less likely to depend on repeated CVE identifiers. If it drops sharply, CVE-level generalization becomes the next bottleneck.",
            "",
        ]
    )


def _row(name: str, block: dict[str, Any]) -> str:
    overall = block["overall"]
    group = block["group_metrics"]
    return (
        f"| `{name}` | `{overall['balanced_accuracy']}` | `{overall['vulnerable_recall']}` | "
        f"`{overall['safe_specificity']}` | `{overall['f1']}` | "
        f"`{group['group_all_correct_rate']}` | `{group['orientation_accuracy']}` |"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate PrimeVul paired diff predictions on a CVE-disjoint eval subset.")
    parser.add_argument("--train-metadata", default="data/processed/secure_code_primevul_pair_diff_only_train_balanced_3000_metadata.jsonl")
    parser.add_argument("--eval-metadata", default="data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl")
    parser.add_argument("--predictions", default="outputs/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_eval1800_dedup_predictions.jsonl")
    parser.add_argument("--pair-margin", type=float, default=0.02)
    parser.add_argument("--json-output", default="reports/secure_code_primevul_cve_disjoint_eval_v1.json")
    parser.add_argument("--md-output", default="reports/PRIMEVUL_CVE_DISJOINT_EVAL.md")
    parser.add_argument("--predictions-output", default="outputs/secure_code_primevul_cve_disjoint_pair_coupled_predictions_v1.jsonl")
    args = parser.parse_args()

    report, pair_rows = build_report(
        read_jsonl(ROOT / args.train_metadata),
        read_jsonl(ROOT / args.eval_metadata),
        read_jsonl(ROOT / args.predictions),
        margin=args.pair_margin,
    )
    write_json(ROOT / args.json_output, report)
    write_jsonl(ROOT / args.predictions_output, pair_rows)
    md_path = ensure_parent(ROOT / args.md_output)
    md_path.write_text(render_report(report), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.evaluate_primevul_bucket_router import compute_binary_metrics, compute_group_metrics
from scripts.evaluate_primevul_pair_coupled_router import apply_pair_coupling
from vrf.io_utils import ensure_parent, read_jsonl, write_json, write_jsonl


DEFAULT_FIELDS = ["project", "cve", "commit_id", "file_hash"]


def _value(row: dict[str, Any], field: str) -> str | None:
    value = row.get(field)
    if value is None or value == "":
        return None
    return str(value)


def join_predictions(metadata_rows: list[dict[str, Any]], prediction_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metadata_by_id = {row["id"]: row for row in metadata_rows}
    rows: list[dict[str, Any]] = []
    for prediction in prediction_rows:
        metadata = metadata_by_id.get(prediction["id"])
        if not metadata:
            continue
        rows.append(
            {
                **prediction,
                "pair_key": metadata.get("pair_key"),
                "project": metadata.get("project"),
                "cve": metadata.get("cve"),
                "commit_id": metadata.get("commit_id"),
                "file_hash": metadata.get("file_hash"),
                "func_hash": metadata.get("func_hash"),
                "vulnerability_type": metadata.get("vulnerability_type"),
                "changed_line_bucket": metadata.get("changed_line_bucket") or _bucket_from_pair_text(metadata),
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


def filter_disjoint(
    train_rows: list[dict[str, Any]],
    eval_rows: list[dict[str, Any]],
    *,
    field: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    train_values = {_value(row, field) for row in train_rows if _value(row, field) is not None}
    eval_values = {_value(row, field) for row in eval_rows if _value(row, field) is not None}
    kept = [row for row in eval_rows if _value(row, field) is not None and _value(row, field) not in train_values]
    removed = [row for row in eval_rows if _value(row, field) is not None and _value(row, field) in train_values]
    missing = [row for row in eval_rows if _value(row, field) is None]
    kept_values = {_value(row, field) for row in kept if _value(row, field) is not None}
    labels = Counter(int(row["gold"]) for row in kept)
    return kept, {
        "field": field,
        "train_unique_values": len(train_values),
        "eval_unique_values": len(eval_values),
        "overlap_unique_values": len(train_values & eval_values),
        "eval_rows_before": len(eval_rows),
        "eval_rows_after": len(kept),
        "removed_overlap_rows": len(removed),
        "missing_eval_rows": len(missing),
        "unique_pair_count_after": len({str(row.get("pair_key") or row["id"]) for row in kept}),
        "overlap_after_filter": len(train_values & kept_values),
        "label_counts_after": {"safe": labels.get(0, 0), "vulnerable": labels.get(1, 0)},
        "top_eval_values_after": Counter(_value(row, field) for row in kept).most_common(10),
    }


def evaluate_field(
    train_rows: list[dict[str, Any]],
    eval_rows: list[dict[str, Any]],
    *,
    field: str,
    margin: float,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    disjoint_rows, split = filter_disjoint(train_rows, eval_rows, field=field)
    pair_rows, coupling_counts = apply_pair_coupling(disjoint_rows, margin=margin)
    field_report = {
        "split": split,
        "baseline": {
            "overall": compute_binary_metrics(disjoint_rows),
            "group_metrics": compute_group_metrics(disjoint_rows),
        },
        "pair_coupled": {
            "overall": compute_binary_metrics(pair_rows),
            "group_metrics": compute_group_metrics(pair_rows),
            "coupling_counts": coupling_counts,
        },
    }
    field_report["delta"] = {
        "balanced_accuracy": round(
            field_report["pair_coupled"]["overall"]["balanced_accuracy"]
            - field_report["baseline"]["overall"]["balanced_accuracy"],
            4,
        ),
        "group_all_correct_rate": round(
            field_report["pair_coupled"]["group_metrics"]["group_all_correct_rate"]
            - field_report["baseline"]["group_metrics"]["group_all_correct_rate"],
            4,
        ),
        "orientation_accuracy": round(
            field_report["pair_coupled"]["group_metrics"]["orientation_accuracy"]
            - field_report["baseline"]["group_metrics"]["orientation_accuracy"],
            4,
        ),
    }
    return field_report, pair_rows


def build_report(
    train_metadata: list[dict[str, Any]],
    eval_metadata: list[dict[str, Any]],
    predictions: list[dict[str, Any]],
    *,
    fields: list[str],
    margin: float,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    joined = join_predictions(eval_metadata, predictions)
    field_predictions: dict[str, list[dict[str, Any]]] = {}
    field_reports: dict[str, Any] = {}
    for field in fields:
        field_reports[field], field_predictions[field] = evaluate_field(
            train_metadata,
            joined,
            field=field,
            margin=margin,
        )
    return {
        "status": "ok",
        "scope": "primevul_disjoint_stress_eval",
        "protocol": {
            "source_eval": "pair_diff_only_eval_balanced_1800_dedup",
            "model": "qwen15bcoder_lora_pair_diff_only_3000_v1",
            "pair_coupling_margin": margin,
            "strict_missing_policy": "exclude rows missing the disjoint field",
        },
        "time_disjoint_feasibility": cve_year_feasibility(train_metadata, joined),
        "fields": field_reports,
    }, field_predictions


def cve_year(value: Any) -> str | None:
    match = re.match(r"CVE-(\d{4})-", str(value or ""))
    return match.group(1) if match else None


def cve_year_feasibility(train_rows: list[dict[str, Any]], eval_rows: list[dict[str, Any]]) -> dict[str, Any]:
    train_years = {year for row in train_rows if (year := cve_year(row.get("cve")))}
    eval_years = {year for row in eval_rows if (year := cve_year(row.get("cve")))}
    unseen_eval_years = sorted(eval_years - train_years)
    rows_after = [row for row in eval_rows if cve_year(row.get("cve")) in unseen_eval_years]
    return {
        "status": "not_feasible" if not rows_after else "feasible",
        "reason": "eval has no CVE years absent from paired-diff training metadata" if not rows_after else "",
        "train_years": sorted(train_years),
        "eval_years": sorted(eval_years),
        "unseen_eval_years": unseen_eval_years,
        "eval_rows_after_unseen_year_filter": len(rows_after),
    }


def render_report(report: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Disjoint Stress Evaluation",
        "",
        "This report evaluates the same paired-diff predictions after filtering eval rows whose metadata value appears in paired-diff training metadata.",
        "It is a stress matrix for shortcut/generalization risk, not a newly trained model.",
        "",
        "Time-disjoint feasibility:",
        "",
        f"- Status: `{report['time_disjoint_feasibility']['status']}`",
        f"- Reason: {report['time_disjoint_feasibility']['reason'] or 'unseen eval years are available'}",
        f"- Unseen eval CVE years: `{report['time_disjoint_feasibility']['unseen_eval_years']}`",
        "",
        "## Summary",
        "",
        "| Field | Rows After | Pairs After | Safe/Vuln | Diff BA | Pair BA | Delta BA | Pair Group | Delta Group | Overlap After |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for field, payload in report["fields"].items():
        split = payload["split"]
        baseline = payload["baseline"]["overall"]
        pair = payload["pair_coupled"]["overall"]
        pair_group = payload["pair_coupled"]["group_metrics"]
        labels = split["label_counts_after"]
        lines.append(
            f"| `{field}` | `{split['eval_rows_after']}` | `{split['unique_pair_count_after']}` | "
            f"`{labels['safe']}/{labels['vulnerable']}` | `{baseline['balanced_accuracy']}` | "
            f"`{pair['balanced_accuracy']}` | `{payload['delta']['balanced_accuracy']}` | "
            f"`{pair_group['group_all_correct_rate']}` | `{payload['delta']['group_all_correct_rate']}` | "
            f"`{split['overlap_after_filter']}` |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `project` is the hardest current same-artifact stress split because it removes projects seen during paired-diff training, but the remaining subset is much smaller.",
            "- `cve`, `commit_id`, and `file_hash` mainly test identifier/memorization leakage while preserving most of the paired eval distribution.",
            "- Time-disjoint evaluation is not reported here because the current train/eval sample has no unseen CVE years in eval.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate PrimeVul paired diff predictions under disjoint metadata stress filters.")
    parser.add_argument("--train-metadata", default="data/processed/secure_code_primevul_pair_diff_only_train_balanced_3000_metadata.jsonl")
    parser.add_argument("--eval-metadata", default="data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl")
    parser.add_argument("--predictions", default="outputs/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_eval1800_dedup_predictions.jsonl")
    parser.add_argument("--fields", default=",".join(DEFAULT_FIELDS))
    parser.add_argument("--pair-margin", type=float, default=0.02)
    parser.add_argument("--json-output", default="reports/secure_code_primevul_disjoint_stress_eval_v1.json")
    parser.add_argument("--md-output", default="reports/PRIMEVUL_DISJOINT_STRESS_EVAL.md")
    parser.add_argument("--predictions-dir", default="outputs/primevul_disjoint_stress_v1")
    args = parser.parse_args()

    fields = [field.strip() for field in args.fields.split(",") if field.strip()]
    report, field_predictions = build_report(
        read_jsonl(ROOT / args.train_metadata),
        read_jsonl(ROOT / args.eval_metadata),
        read_jsonl(ROOT / args.predictions),
        fields=fields,
        margin=args.pair_margin,
    )
    write_json(ROOT / args.json_output, report)
    md_path = ensure_parent(ROOT / args.md_output)
    md_path.write_text(render_report(report), encoding="utf-8")
    predictions_dir = ROOT / args.predictions_dir
    predictions_dir.mkdir(parents=True, exist_ok=True)
    for field, rows in field_predictions.items():
        write_jsonl(predictions_dir / f"{field}_pair_coupled_predictions.jsonl", rows)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

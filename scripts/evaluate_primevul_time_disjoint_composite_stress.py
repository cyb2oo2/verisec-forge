from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.evaluate_primevul_bucket_router import compute_binary_metrics, compute_group_metrics
from scripts.evaluate_primevul_pair_coupled_router import apply_pair_coupling
from scripts.evaluate_primevul_time_disjoint_transfer import _bucket_from_pair_text
from vrf.io_utils import ensure_parent, read_jsonl, write_json


DEFAULT_SCENARIOS = {
    "time_only": [],
    "time_project_disjoint": ["project"],
    "time_file_hash_disjoint": ["file_hash"],
    "time_project_file_hash_disjoint": ["project", "file_hash"],
    "time_project_cve_commit_file_disjoint": ["project", "cve", "commit_id", "file_hash"],
}


def _value(row: dict[str, Any], field: str) -> str | None:
    value = row.get(field)
    if value is None or value == "":
        return None
    return str(value)


def join_predictions(metadata_rows: list[dict[str, Any]], prediction_rows: list[dict[str, Any]], *, threshold: float) -> list[dict[str, Any]]:
    metadata_by_id = {str(row["id"]): row for row in metadata_rows}
    rows: list[dict[str, Any]] = []
    for prediction in prediction_rows:
        metadata = metadata_by_id.get(str(prediction["id"]))
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
                "commit_id": metadata.get("commit_id"),
                "file_hash": metadata.get("file_hash"),
                "func_hash": metadata.get("func_hash"),
                "vulnerability_type": metadata.get("vulnerability_type"),
                "changed_line_bucket": metadata.get("changed_line_bucket") or _bucket_from_pair_text(metadata),
            }
        )
    return rows


def filter_by_constraints(
    train_rows: list[dict[str, Any]],
    eval_rows: list[dict[str, Any]],
    *,
    fields: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    kept = list(eval_rows)
    field_reports: dict[str, Any] = {}
    for field in fields:
        train_values = {_value(row, field) for row in train_rows if _value(row, field) is not None}
        before = len(kept)
        before_pairs = len({str(row.get("pair_key") or row["id"]) for row in kept})
        missing = [row for row in kept if _value(row, field) is None]
        overlap = [row for row in kept if _value(row, field) is not None and _value(row, field) in train_values]
        kept = [row for row in kept if _value(row, field) is not None and _value(row, field) not in train_values]
        kept_values = {_value(row, field) for row in kept if _value(row, field) is not None}
        field_reports[field] = {
            "train_unique_values": len(train_values),
            "rows_before": before,
            "pairs_before": before_pairs,
            "removed_overlap_rows": len(overlap),
            "removed_missing_rows": len(missing),
            "rows_after": len(kept),
            "pairs_after": len({str(row.get("pair_key") or row["id"]) for row in kept}),
            "overlap_after_filter": len(train_values & kept_values),
        }
    labels = Counter(int(row["gold"]) for row in kept)
    return kept, {
        "constraints": fields,
        "rows_after": len(kept),
        "unique_pair_count_after": len({str(row.get("pair_key") or row["id"]) for row in kept}),
        "label_counts_after": {"safe": labels.get(0, 0), "vulnerable": labels.get(1, 0)},
        "field_filters": field_reports,
    }


def evaluate_scenario(
    train_rows: list[dict[str, Any]],
    joined_eval_rows: list[dict[str, Any]],
    *,
    fields: list[str],
    margin: float,
) -> dict[str, Any]:
    filtered, split = filter_by_constraints(train_rows, joined_eval_rows, fields=fields)
    pair_rows, coupling_counts = apply_pair_coupling(filtered, margin=margin)
    report = {
        "split": split,
        "baseline": {
            "overall": compute_binary_metrics(filtered),
            "group_metrics": compute_group_metrics(filtered),
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
    return report


def parse_scenarios(raw: str) -> dict[str, list[str]]:
    if raw == "default":
        return DEFAULT_SCENARIOS
    scenarios: dict[str, list[str]] = {}
    for item in raw.split(";"):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise ValueError(f"Scenario must use name=field,field syntax: {item}")
        name, fields = item.split("=", 1)
        scenarios[name.strip()] = [field.strip() for field in fields.split(",") if field.strip()]
    return scenarios


def build_report(
    train_metadata: list[dict[str, Any]],
    eval_metadata: list[dict[str, Any]],
    predictions: list[dict[str, Any]],
    *,
    threshold: float,
    margin: float,
    scenarios: dict[str, list[str]],
) -> dict[str, Any]:
    joined = join_predictions(eval_metadata, predictions, threshold=threshold)
    train_years = sorted({int(row["cve_year"]) for row in train_metadata if row.get("cve_year") is not None})
    eval_years = sorted({int(row["cve_year"]) for row in eval_metadata if row.get("cve_year") is not None})
    train_cves = {str(row.get("cve")) for row in train_metadata if row.get("cve")}
    eval_cves = {str(row.get("cve")) for row in eval_metadata if row.get("cve")}
    train_pair_keys = {str(row.get("pair_key")) for row in train_metadata if row.get("pair_key")}
    eval_pair_keys = {str(row.get("pair_key")) for row in eval_metadata if row.get("pair_key")}
    return {
        "status": "ok",
        "scope": "primevul_time_disjoint_composite_stress",
        "protocol": {
            "train_condition": "CVE-year <=2020",
            "eval_condition": "CVE-year >=2021",
            "threshold": threshold,
            "pair_coupling_margin": margin,
            "strict_missing_policy": "exclude rows missing each requested disjoint field",
        },
        "base_split": {
            "train_rows": len(train_metadata),
            "eval_rows": len(joined),
            "train_years": train_years,
            "eval_years": eval_years,
            "cve_overlap": len(train_cves & eval_cves),
            "pair_key_overlap": len(train_pair_keys & eval_pair_keys),
        },
        "scenarios": {
            name: evaluate_scenario(train_metadata, joined, fields=fields, margin=margin)
            for name, fields in scenarios.items()
        },
    }


def render_report(report: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Time-Disjoint Composite Stress Evaluation",
        "",
        "This report evaluates the direct time-split detector under stricter composite filters.",
        "The base split is already temporal: train `<=2020`, eval `>=2021`, with zero CVE and pair-key overlap.",
        "",
        "## Base Split",
        "",
        f"- Train rows: `{report['base_split']['train_rows']}`",
        f"- Eval rows: `{report['base_split']['eval_rows']}`",
        f"- Train years: `{report['base_split']['train_years']}`",
        f"- Eval years: `{report['base_split']['eval_years']}`",
        f"- CVE overlap: `{report['base_split']['cve_overlap']}`",
        f"- Pair-key overlap: `{report['base_split']['pair_key_overlap']}`",
        "",
        "## Results",
        "",
        "| Scenario | Constraints | Rows | Pairs | Safe/Vuln | Baseline BA | Pair BA | Delta BA | Pair Group | Delta Group |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, payload in report["scenarios"].items():
        split = payload["split"]
        labels = split["label_counts_after"]
        baseline = payload["baseline"]["overall"]
        pair = payload["pair_coupled"]["overall"]
        pair_group = payload["pair_coupled"]["group_metrics"]
        constraints = ", ".join(split["constraints"]) if split["constraints"] else "time only"
        lines.append(
            f"| `{name}` | `{constraints}` | `{split['rows_after']}` | `{split['unique_pair_count_after']}` | "
            f"`{labels['safe']}/{labels['vulnerable']}` | `{baseline['balanced_accuracy']}` | "
            f"`{pair['balanced_accuracy']}` | `{payload['delta']['balanced_accuracy']}` | "
            f"`{pair_group['group_all_correct_rate']}` | `{payload['delta']['group_all_correct_rate']}` |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `time_only` is the full later-CVE eval split for the direct time-trained detector.",
            "- `time_project_disjoint` asks whether the result survives when later-CVE eval rows from training-period projects are removed.",
            "- `time_project_cve_commit_file_disjoint` is the strictest current composite slice. In this PrimeVul sample, CVE and commit are already disjoint under the time split; the extra pressure mainly comes from project and file-hash filtering.",
            "- These are stress slices, not new training runs. Small composite slices should be treated as reviewer-facing robustness evidence rather than headline benchmark scores.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate time-disjoint PrimeVul predictions under composite disjoint stress filters.")
    parser.add_argument("--train-metadata", default="data/processed/secure_code_primevul_pair_diff_time_train_le2020_balanced_6000_metadata.jsonl")
    parser.add_argument("--eval-metadata", default="data/processed/secure_code_primevul_pair_diff_time_eval_ge2021_balanced_2000_metadata.jsonl")
    parser.add_argument("--predictions", default="outputs/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_time_le2020_v1_eval_ge2021_predictions.jsonl")
    parser.add_argument("--threshold", type=float, default=0.6)
    parser.add_argument("--pair-margin", type=float, default=0.02)
    parser.add_argument("--scenarios", default="default")
    parser.add_argument("--json-output", default="reports/secure_code_primevul_time_disjoint_composite_stress_v1.json")
    parser.add_argument("--md-output", default="reports/PRIMEVUL_TIME_DISJOINT_COMPOSITE_STRESS.md")
    args = parser.parse_args()

    report = build_report(
        read_jsonl(ROOT / args.train_metadata),
        read_jsonl(ROOT / args.eval_metadata),
        read_jsonl(ROOT / args.predictions),
        threshold=args.threshold,
        margin=args.pair_margin,
        scenarios=parse_scenarios(args.scenarios),
    )
    write_json(ROOT / args.json_output, report)
    ensure_parent(ROOT / args.md_output).write_text(render_report(report), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
from vrf.io_utils import ensure_parent, read_jsonl, write_json


def join_predictions(metadata_rows: list[dict[str, Any]], predictions: list[dict[str, Any]], *, threshold: float) -> list[dict[str, Any]]:
    metadata_by_id = {str(row["id"]): row for row in metadata_rows}
    rows: list[dict[str, Any]] = []
    for prediction in predictions:
        metadata = metadata_by_id.get(str(prediction["id"]))
        if not metadata:
            continue
        probability = float(prediction["vuln_probability"])
        rows.append(
            {
                **prediction,
                "gold": int(bool(metadata.get("has_vulnerability"))),
                "pred": int(probability >= threshold),
                "pair_key": metadata.get("pair_key"),
                "project": metadata.get("project"),
                "cwe": metadata.get("cwe"),
                "vulnerability_type": metadata.get("vulnerability_type"),
                "changed_line_bucket": metadata.get("changed_line_bucket"),
                "file_extension": metadata.get("file_extension"),
            }
        )
    return rows


def build_report(
    metadata_rows: list[dict[str, Any]],
    predictions: list[dict[str, Any]],
    *,
    threshold: float,
    margin: float,
    checkpoint_label: str,
    scope: str,
    target_training: str,
    source_dataset: str = "rufimelo/DeltaSecommits",
) -> dict[str, Any]:
    threshold_rows = join_predictions(metadata_rows, predictions, threshold=threshold)
    pair_rows, coupling_counts = apply_pair_coupling(threshold_rows, margin=margin)
    labels = Counter(int(row["gold"]) for row in threshold_rows)
    buckets = Counter(str(row.get("changed_line_bucket") or "unknown") for row in threshold_rows)
    return {
        "status": "ok",
        "scope": scope,
        "protocol": {
            "source_dataset": source_dataset,
            "checkpoint": checkpoint_label,
            "threshold": threshold,
            "pair_coupling_margin": margin,
            "target_training": target_training,
        },
        "split": {
            "rows": len(threshold_rows),
            "unique_pair_count": len({str(row.get("pair_key") or row["id"]) for row in threshold_rows}),
            "label_counts": {"safe": labels.get(0, 0), "vulnerable": labels.get(1, 0)},
            "changed_line_buckets": dict(sorted(buckets.items())),
        },
        "default_threshold": {
            "overall": compute_binary_metrics(threshold_rows),
            "group_metrics": compute_group_metrics(threshold_rows),
        },
        "pair_coupled": {
            "overall": compute_binary_metrics(pair_rows),
            "group_metrics": compute_group_metrics(pair_rows),
            "coupling_counts": coupling_counts,
        },
    }


def render_report(report: dict[str, Any], *, title: str) -> str:
    default = report["default_threshold"]
    pair = report["pair_coupled"]
    return "\n".join(
        [
            f"# {title}",
            "",
            f"This report evaluates paired-diff detector predictions on `{report['protocol']['source_dataset']}` paired vulnerable/secure snapshots.",
            f"Target training: {report['protocol']['target_training']}.",
            "",
            "## Protocol",
            "",
            f"- Source dataset: `{report['protocol']['source_dataset']}`",
            f"- Checkpoint: `{report['protocol']['checkpoint']}`",
            f"- Threshold: `{report['protocol']['threshold']}`",
            f"- Pair-coupling margin: `{report['protocol']['pair_coupling_margin']}`",
            "",
            "## Split",
            "",
            f"- Rows: `{report['split']['rows']}`",
            f"- Pair groups: `{report['split']['unique_pair_count']}`",
            f"- Safe/vulnerable: `{report['split']['label_counts']['safe']}/{report['split']['label_counts']['vulnerable']}`",
            "",
            "## Results",
            "",
            "| System | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            _row("default threshold", default["overall"], default["group_metrics"]),
            _row("pair-coupled", pair["overall"], pair["group_metrics"]),
            "",
            "## Interpretation",
            "",
            "This is a cross-source paired-diff transfer check. If it is much lower than PrimeVul, that is useful negative evidence: the system has learned the PrimeVul paired-diff formulation, but cross-dataset patch semantics may need source-specific calibration, source-aware adapters, or a mixed-source detector.",
            "",
        ]
    )


def _row(name: str, overall: dict[str, Any], group: dict[str, Any]) -> str:
    return (
        f"| `{name}` | `{overall['balanced_accuracy']}` | `{overall['vulnerable_recall']}` | "
        f"`{overall['safe_specificity']}` | `{overall['precision']}` | `{overall['f1']}` | "
        f"`{group['group_all_correct_rate']}` | `{group['orientation_accuracy']}` |"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate DeltaSecommits zero-shot transfer from a PrimeVul paired-diff checkpoint.")
    parser.add_argument("--metadata", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_all_metadata.jsonl")
    parser.add_argument("--predictions", default="outputs/secure_code_deltasecommits_primevul_time_checkpoint_zero_shot_predictions.jsonl")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--pair-margin", type=float, default=0.02)
    parser.add_argument("--checkpoint-label", default="cls_secure_code_primevul_qwen15bcoder_lora_pair_diff_time_le2020_v1")
    parser.add_argument("--scope", default="deltasecommits_zero_shot_primevul_checkpoint")
    parser.add_argument("--target-training", default="none; zero-shot cross-source evaluation")
    parser.add_argument("--source-dataset", default="rufimelo/DeltaSecommits")
    parser.add_argument("--title", default="DeltaSecommits Zero-Shot Transfer Evaluation")
    parser.add_argument("--json-output", default="reports/secure_code_deltasecommits_zero_shot_primevul_time_checkpoint_v1.json")
    parser.add_argument("--md-output", default="reports/DELTASECCOMMITS_ZERO_SHOT_PRIMEVUL_TIME_CHECKPOINT.md")
    args = parser.parse_args()

    report = build_report(
        read_jsonl(ROOT / args.metadata),
        read_jsonl(ROOT / args.predictions),
        threshold=args.threshold,
        margin=args.pair_margin,
        checkpoint_label=args.checkpoint_label,
        scope=args.scope,
        target_training=args.target_training,
        source_dataset=args.source_dataset,
    )
    write_json(ROOT / args.json_output, report)
    ensure_parent(ROOT / args.md_output).write_text(render_report(report, title=args.title), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

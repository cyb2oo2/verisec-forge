from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_jsonl
from vrf.pair_annotation import ANNOTATION_FIELDS, build_blinded_packet, select_high_value_pairs


def changed_lines(pair_text: str) -> int:
    return sum(
        1
        for line in str(pair_text).splitlines()
        if (line.startswith("+") and not line.startswith("+++")) or (line.startswith("-") and not line.startswith("---"))
    )


def build_pair_pool(dataset_rows: list[dict[str, Any]], prediction_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    predictions = {str(row["id"]): row for row in prediction_rows}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in dataset_rows:
        grouped.setdefault(str(row.get("pair_key") or row["id"]), []).append(row)

    pairs: list[dict[str, Any]] = []
    for pair_key, rows in grouped.items():
        if len(rows) != 2:
            continue
        probabilities = [float(predictions.get(str(row["id"]), {}).get("vuln_probability") or 0.0) for row in rows]
        predictions_for_pair = [int(predictions.get(str(row["id"]), {}).get("pred", 0)) for row in rows]
        gold = [int(bool(row.get("has_vulnerability"))) for row in rows]
        vulnerable_rows = [row for row in rows if bool(row.get("has_vulnerability"))]
        pairs.append(
            {
                "pair_key": pair_key,
                "rows": rows,
                "gold_vulnerable_id": vulnerable_rows[0]["id"] if len(vulnerable_rows) == 1 else None,
                "probability_gap": abs(probabilities[0] - probabilities[1]),
                "model_pair_correct": predictions_for_pair == gold,
                "changed_lines": max(changed_lines(row.get("pair_text", "")) for row in rows),
            }
        )
    return pairs


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ANNOTATION_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a blinded two-annotator secure patch-pair study.")
    parser.add_argument("--dataset", default="data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl")
    parser.add_argument("--predictions", default="outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl")
    parser.add_argument("--sample-size", type=int, default=150)
    parser.add_argument("--seed", type=int, default=20260608)
    parser.add_argument("--output-dir", default="data/annotation/primevul_pair_study_v1")
    parser.add_argument("--summary-output", default="reports/secure_code_primevul_pair_annotation_study_v1.json")
    args = parser.parse_args()

    pool = build_pair_pool(read_jsonl(ROOT / args.dataset), read_jsonl(ROOT / args.predictions))
    selected = select_high_value_pairs(pool, sample_size=args.sample_size, seed=args.seed)
    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    mapping_rows: list[dict[str, Any]] = []
    for offset, annotator_id in enumerate(["annotator_1", "annotator_2"], start=1):
        packet, answers, mappings = build_blinded_packet(
            selected,
            annotator_id=annotator_id,
            seed=args.seed + offset,
        )
        write_jsonl(output_dir / f"{annotator_id}_packet.jsonl", packet)
        write_csv(output_dir / f"{annotator_id}_answers.csv", answers)
        mapping_rows.extend(mappings)
    write_jsonl(output_dir / "private_case_mapping.jsonl", mapping_rows)

    strata: dict[str, int] = {}
    for row in selected:
        strata[row["selection_stratum"]] = strata.get(row["selection_stratum"], 0) + 1
    summary = {
        "status": "ok",
        "protocol": "two_independent_blinded_annotators",
        "requested_pairs": args.sample_size,
        "materialized_pairs": len(selected),
        "candidate_pairs": len(pool),
        "selection_strata": dict(sorted(strata.items())),
        "output_dir": args.output_dir.replace("\\", "/"),
        "annotation_fields": ANNOTATION_FIELDS,
        "minimum_publishable_gate": {
            "completed_by_both_annotators": 100,
            "target_completed_by_both_annotators": min(150, len(selected)),
            "report_side_cohen_kappa": True,
            "report_context_cohen_kappa": True,
            "adjudicate_all_disagreements": True,
        },
    }
    summary_path = ROOT / args.summary_output
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

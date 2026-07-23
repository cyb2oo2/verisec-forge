from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_jsonl
from vrf.pair_annotation import (
    analyze_independent_annotations,
    apply_adjudications,
    exact_dual_agreement_rows,
)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build human_gold_consensus_v1.jsonl from exact dual agreements "
            "plus human-adjudicated disagreements. Does not invent labels."
        )
    )
    parser.add_argument("--study-dir", default="data/annotation/primevul_pair_study_v1")
    parser.add_argument("--adjudications", default="")
    parser.add_argument("--output", default="")
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_primevul_pair_annotation_adjudication_v1.json",
    )
    args = parser.parse_args()
    study_dir = ROOT / args.study_dir
    a_path = study_dir / "annotator_1_answers.csv"
    b_path = study_dir / "annotator_2_answers.csv"
    if not a_path.exists() or not b_path.exists():
        print(
            json.dumps(
                {
                    "status": "not_applicable_single_author",
                    "message": (
                        "Dual-annotator CSVs missing; adjudication/consensus export "
                        "is dual_independent only. For single-author studies use "
                        "annotator_answers.csv completion status instead."
                    ),
                    "study_dir": study_dir.relative_to(ROOT).as_posix()
                    if study_dir.is_relative_to(ROOT)
                    else str(study_dir),
                },
                indent=2,
            )
        )
        return 0

    mappings = read_jsonl(study_dir / "private_case_mapping.jsonl")
    annotations_a = read_csv(a_path)
    annotations_b = read_csv(b_path)
    agreement = analyze_independent_annotations(annotations_a, annotations_b, mappings)
    exact_agreements = exact_dual_agreement_rows(annotations_a, annotations_b, mappings)

    adj_path = ROOT / (args.adjudications or str(study_dir / "adjudication_template.csv"))
    adjudication_rows: list[dict[str, str]] = []
    if adj_path.exists():
        adjudication_rows = read_csv(adj_path)
    elif agreement.get("disagreement_count", 0) > 0:
        print(json.dumps({"status": "failed", "message": f"missing adjudications file: {adj_path}"}))
        return 1

    result = apply_adjudications(
        agreement.get("disagreements") or [],
        adjudication_rows,
        mappings,
        exact_agreements=exact_agreements,
    )
    out_path = ROOT / (args.output or str(study_dir / "human_gold_consensus_v1.jsonl"))
    write_jsonl(out_path, result["consensus"])
    summary = {
        "status": result["status"],
        "consensus_count": result["consensus_count"],
        "exact_agreement_count": result.get("exact_agreement_count", 0),
        "adjudicated_disagreement_count": result.get("adjudicated_disagreement_count", 0),
        "disagreement_count": result["disagreement_count"],
        "missing_disagreement_pair_keys": result["missing_disagreement_pair_keys"],
        "all_disagreements_adjudicated": result["all_disagreements_adjudicated"],
        "output": out_path.relative_to(ROOT).as_posix(),
        "claim_boundary": result["claim_boundary"],
        "note": (
            "Consensus gold = exact dual agreements (auto) + human-adjudicated "
            "disagreements. AI must not fill adjudication CSVs."
        ),
    }
    summary_path = ROOT / args.summary_output
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    if result["disagreement_count"] == 0:
        return 0
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

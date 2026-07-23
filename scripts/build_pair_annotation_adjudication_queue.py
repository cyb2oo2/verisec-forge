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
    ADJUDICATION_FIELDS,
    analyze_independent_annotations,
    empty_adjudication_template_rows,
)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build human-only adjudication queue from dual-complete disagreements."
    )
    parser.add_argument("--study-dir", default="data/annotation/primevul_pair_study_v1")
    parser.add_argument("--output-template", default="")
    parser.add_argument("--output-queue", default="")
    args = parser.parse_args()
    study_dir = ROOT / args.study_dir
    mappings = read_jsonl(study_dir / "private_case_mapping.jsonl")
    report = analyze_independent_annotations(
        read_csv(study_dir / "annotator_1_answers.csv"),
        read_csv(study_dir / "annotator_2_answers.csv"),
        mappings,
    )
    disagreements = report.get("disagreements") or []
    template_rows = empty_adjudication_template_rows(disagreements)
    template_path = ROOT / (
        args.output_template or str(study_dir / "adjudication_template.csv")
    )
    write_csv(template_path, template_rows, ADJUDICATION_FIELDS)

    # Queue includes disagreement metadata + private mapping ids (adjudicator-only; not for annotators).
    mapping_by_pair: dict[str, dict] = {}
    for row in mappings:
        mapping_by_pair.setdefault(str(row["pair_key"]), row)
    queue = []
    for item in disagreements:
        pair_key = str(item["pair_key"])
        mapping = mapping_by_pair.get(pair_key, {})
        queue.append(
            {
                **item,
                "side_a_id_annotator_agnostic": sorted(
                    [str(mapping.get("side_a_id") or ""), str(mapping.get("side_b_id") or "")]
                ),
                "selection_stratum": mapping.get("selection_stratum") or item.get("selection_stratum"),
                "instruction": (
                    "Human adjudicator only. Decide consensus_vulnerable_side_id as the sample id of the "
                    "vulnerable side (from mapping), and consensus_context_sufficient in {yes,no,unclear}. "
                    "Do not use AI to fill consensus. Optionally compare to benchmark gold only AFTER recording consensus."
                ),
            }
        )
    queue_path = ROOT / (args.output_queue or str(study_dir / "adjudication_queue.jsonl"))
    write_jsonl(queue_path, queue)
    summary = {
        "status": report.get("status"),
        "dual_complete_n": report.get("dual_complete_n"),
        "disagreement_count": len(disagreements),
        "template": template_path.relative_to(ROOT).as_posix(),
        "queue": queue_path.relative_to(ROOT).as_posix(),
        "claim_boundary": "human_adjudication_not_ai_gold",
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

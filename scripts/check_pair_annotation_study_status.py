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

from vrf.io_utils import read_jsonl
from vrf.pair_annotation import (
    DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE,
    DEFAULT_SINGLE_AUTHOR_SEED,
    single_author_study_id,
    single_author_study_status,
    study_status,
)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    parser = argparse.ArgumentParser(description="Report completion status for the pair annotation study.")
    parser.add_argument("--study-dir", default="data/annotation/primevul_pair_study_v1")
    parser.add_argument("--output", default="reports/secure_code_primevul_pair_annotation_status_v1.json")
    parser.add_argument("--target-pairs", type=int, default=DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE)
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SINGLE_AUTHOR_SEED,
        help="Seed used when resolving single-author study_id provenance.",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "single_author", "dual_independent"],
        default="auto",
    )
    args = parser.parse_args()
    study_dir = ROOT / args.study_dir
    mappings = read_jsonl(study_dir / "private_case_mapping.jsonl")

    mode = args.mode
    if mode == "auto":
        if (study_dir / "annotator_answers.csv").exists():
            mode = "single_author"
        elif (study_dir / "annotator_1_answers.csv").exists():
            mode = "dual_independent"
        else:
            mode = "single_author"

    if mode == "single_author":
        answers_path = study_dir / "annotator_answers.csv"
        if not answers_path.exists():
            raise SystemExit(f"missing {answers_path}")
        report = single_author_study_status(
            read_csv(answers_path),
            mappings,
            target_pairs=args.target_pairs,
            study_id=single_author_study_id(args.target_pairs, args.seed),
            seed=args.seed,
        )
    else:
        report = study_status(
            read_csv(study_dir / "annotator_1_answers.csv"),
            read_csv(study_dir / "annotator_2_answers.csv"),
            mappings,
            target_pairs=args.target_pairs,
            minimum_publishable_dual_complete=min(100, args.target_pairs),
        )

    out = ROOT / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

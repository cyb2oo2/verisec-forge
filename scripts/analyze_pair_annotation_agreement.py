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
from vrf.pair_annotation import analyze_independent_annotations


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze agreement for the two-annotator patch-pair study.")
    parser.add_argument("--study-dir", default="data/annotation/primevul_pair_study_v1")
    parser.add_argument("--output", default="reports/secure_code_primevul_pair_annotation_agreement_v1.json")
    args = parser.parse_args()
    study_dir = ROOT / args.study_dir
    report = analyze_independent_annotations(
        read_csv(study_dir / "annotator_1_answers.csv"),
        read_csv(study_dir / "annotator_2_answers.csv"),
        read_jsonl(study_dir / "private_case_mapping.jsonl"),
    )
    (ROOT / args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

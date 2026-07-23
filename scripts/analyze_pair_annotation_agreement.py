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
    STUDY_ID_SINGLE_AUTHOR_50,
    analyze_independent_annotations,
    not_applicable_agreement_report,
    render_agreement_markdown,
)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze dual-annotator agreement. When the study dir is single-author "
            "(annotator_answers.csv without annotator_1/2), writes a not_applicable "
            "report instead of dual IAA metrics."
        )
    )
    parser.add_argument("--study-dir", default="data/annotation/primevul_pair_study_v1")
    parser.add_argument("--output", default="reports/secure_code_primevul_pair_annotation_agreement_v1.json")
    parser.add_argument("--markdown-output", default="reports/PRIMEVUL_PAIR_ANNOTATION_AGREEMENT_V1.md")
    parser.add_argument(
        "--study-id",
        default=STUDY_ID_SINGLE_AUTHOR_50,
        help="Study id recorded on not_applicable_single_author reports.",
    )
    args = parser.parse_args()
    study_dir = ROOT / args.study_dir
    a_path = study_dir / "annotator_1_answers.csv"
    b_path = study_dir / "annotator_2_answers.csv"
    single_path = study_dir / "annotator_answers.csv"

    if single_path.exists() and not (a_path.exists() and b_path.exists()):
        report = not_applicable_agreement_report(study_id=args.study_id)
    elif not a_path.exists() or not b_path.exists():
        report = not_applicable_agreement_report(
            study_id=args.study_id,
            reason="dual_annotator_csvs_missing",
        )
        report["note"] = (
            "Dual annotator CSVs missing; agreement not computed. "
            "Use mode=dual_independent with annotator_1/2 answer sheets, "
            "or treat as single-author (no κ)."
        )
    else:
        report = analyze_independent_annotations(
            read_csv(a_path),
            read_csv(b_path),
            read_jsonl(study_dir / "private_case_mapping.jsonl"),
        )

    out = ROOT / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path = ROOT / args.markdown_output
    md_path.write_text(render_agreement_markdown(report), encoding="utf-8")
    printable = {k: report[k] for k in report if k != "disagreements"}
    print(json.dumps(printable, indent=2))
    print(f"status={report.get('status')} markdown={md_path.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

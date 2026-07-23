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

from vrf.pair_annotation import validate_answer_rows


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate annotator answer CSV enums and completeness.")
    parser.add_argument(
        "--answers",
        default="data/annotation/primevul_pair_study_v1/annotator_answers.csv",
        help="Path to annotator answers CSV (default: single-author template)",
    )
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    report = validate_answer_rows(read_csv(ROOT / args.answers if not Path(args.answers).is_absolute() else Path(args.answers)))
    text = json.dumps(report, indent=2)
    print(text)
    if args.output:
        out = ROOT / args.output
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

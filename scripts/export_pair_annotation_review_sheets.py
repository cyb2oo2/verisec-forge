from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl
from vrf.pair_annotation import export_review_sheet_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Export Markdown review sheets from blinded packets.")
    parser.add_argument("--study-dir", default="data/annotation/primevul_pair_study_v1")
    parser.add_argument(
        "--annotator",
        default="author",
        help="author (default single-author packet), annotator_1/2 (legacy dual), or both (legacy).",
    )
    parser.add_argument("--output-dir", default="")
    args = parser.parse_args()
    study_dir = ROOT / args.study_dir
    output_dir = ROOT / (args.output_dir or str(study_dir / "review_sheets"))
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.annotator == "both":
        targets = ["annotator_1", "annotator_2"]
    elif args.annotator == "author":
        targets = ["author"]
    else:
        targets = [args.annotator]

    for annotator_id in targets:
        if annotator_id == "author":
            packet_path = study_dir / "annotator_packet.jsonl"
            out_name = "annotator_review.md"
        else:
            packet_path = study_dir / f"{annotator_id}_packet.jsonl"
            out_name = f"{annotator_id}_review.md"
        if not packet_path.exists():
            raise SystemExit(f"missing packet: {packet_path}")
        packet = read_jsonl(packet_path)
        markdown = export_review_sheet_markdown(packet, annotator_id=annotator_id)
        path = output_dir / out_name
        path.write_text(markdown, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT).as_posix()} cases={len(packet)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

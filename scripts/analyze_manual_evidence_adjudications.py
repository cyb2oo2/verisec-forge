from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scripts.export_manual_evidence_adjudication_template import DEFAULT_QUEUE_PATHS, load_queue_rows
from vrf.evidence_adjudication import analyze_adjudications
from vrf.io_utils import ensure_parent, read_jsonl, write_json


def _count_lines(counts: dict[str, object]) -> list[str]:
    if not counts:
        return ["- None yet."]
    return [f"- `{key}`: `{value}`" for key, value in sorted(counts.items())]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze completed manual evidence adjudications.",
    )
    parser.add_argument(
        "--input",
        default="data/processed/secure_code_primevul_manual_evidence_adjudicated_queues_v1.jsonl",
        help="Adjudicated queue JSONL. If missing, falls back to unadjudicated queue inputs.",
    )
    parser.add_argument("--queues", nargs="+", default=DEFAULT_QUEUE_PATHS)
    parser.add_argument(
        "--json-output",
        default="reports/secure_code_primevul_manual_evidence_adjudication_analysis_v1.json",
    )
    parser.add_argument(
        "--md-output",
        default="reports/PRIMEVUL_MANUAL_EVIDENCE_ADJUDICATION_ANALYSIS.md",
    )
    return parser.parse_args()


def render_report(payload: dict[str, object], input_path: str) -> str:
    return "\n".join(
        [
            "# PrimeVul Manual Evidence Adjudication Analysis",
            "",
            f"- Input: `{input_path}`",
            f"- Rows: `{payload['rows']}`",
            f"- Completed adjudications: `{payload['completed_adjudications']}`",
            f"- Completion rate: `{payload['completion_rate']}`",
            f"- Invalid adjudications: `{payload['invalid_adjudications']}`",
            "",
            "## Label Status Counts",
            "",
            *_count_lines(payload["label_status_counts"]),
            "",
            "## Evidence Span Sufficiency",
            "",
            *_count_lines(payload["evidence_span_sufficiency_counts"]),
            "",
            "## Reviewers",
            "",
            *_count_lines(payload["reviewer_counts"]),
            "",
            "## By Queue Type",
            "",
            *(
                [
                    f"- `{queue_type}`: " + ", ".join(f"{key}=`{value}`" for key, value in sorted(counts.items()))
                    for queue_type, counts in sorted(payload["by_queue_type"].items())
                ]
                if payload["by_queue_type"]
                else ["- None yet."]
            ),
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    input_path = ROOT / args.input
    if input_path.exists():
        rows = read_jsonl(input_path)
        source = args.input
    else:
        rows = load_queue_rows(args.queues)
        source = " + ".join(args.queues)
    payload = analyze_adjudications(rows)
    write_json(ROOT / args.json_output, payload)
    md_path = ensure_parent(ROOT / args.md_output)
    md_path.write_text(render_report(payload, source.replace("\\", "/")), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 1 if payload["invalid_adjudications"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

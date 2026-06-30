from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.evidence_adjudication import analyze_adjudications
from vrf.io_utils import ensure_parent, read_jsonl, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize applied manual evidence adjudication rows (label status, "
        "evidence sufficiency, and reviewer counts).",
    )
    parser.add_argument("--input", required=True, help="Applied adjudication JSONL path.")
    parser.add_argument(
        "--queues",
        nargs="*",
        default=[],
        help="Optional original queue JSONL paths, retained for parity with the apply step.",
    )
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output", required=True)
    return parser.parse_args()


def render_report(payload: dict[str, object]) -> str:
    def _format_mapping(mapping: dict[str, object]) -> str:
        if not mapping:
            return "`{}`"
        return "`" + ", ".join(f"{key}: {value}" for key, value in sorted(mapping.items())) + "`"

    lines = [
        "# Manual Evidence Adjudication Analysis",
        "",
        "This report summarizes an applied manual evidence adjudication JSONL file.",
        "It does not re-derive verdicts; it counts what reviewers already recorded.",
        "",
        "## Summary",
        "",
        f"- Rows: `{payload['rows']}`",
        f"- Completed adjudications: `{payload['completed_adjudications']}`",
        f"- Completion rate: `{payload['completion_rate']}`",
        f"- Invalid adjudications: `{payload['invalid_adjudications']}`",
        f"- Label status counts: {_format_mapping(payload['label_status_counts'])}",
        f"- Evidence span sufficiency counts: {_format_mapping(payload['evidence_span_sufficiency_counts'])}",
        f"- Reviewer counts: {_format_mapping(payload['reviewer_counts'])}",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    rows = read_jsonl(ROOT / args.input)
    payload = analyze_adjudications(rows)
    write_json(ensure_parent(ROOT / args.json_output), payload)
    md_path = ensure_parent(ROOT / args.md_output)
    md_path.write_text(render_report(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

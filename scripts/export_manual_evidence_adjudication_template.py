from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.evidence_adjudication import adjudication_template_rows
from vrf.io_utils import ensure_parent, read_jsonl, write_csv, write_json


DEFAULT_QUEUE_PATHS = [
    "data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_v1.jsonl",
    "data/processed/secure_code_primevul_manual_evidence_insufficient_context_v1.jsonl",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export a CSV template for independent manual evidence adjudication.",
    )
    parser.add_argument("--queues", nargs="+", default=DEFAULT_QUEUE_PATHS)
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_primevul_manual_evidence_adjudication_template_v1.csv",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_primevul_manual_evidence_adjudication_template_v1.json",
    )
    parser.add_argument(
        "--report-output",
        default="reports/PRIMEVUL_MANUAL_EVIDENCE_ADJUDICATION_WORKFLOW.md",
    )
    return parser.parse_args()


def load_queue_rows(paths: list[str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in paths:
        rows.extend(read_jsonl(ROOT / path))
    return rows


def render_report(payload: dict[str, object]) -> str:
    return "\n".join(
        [
            "# PrimeVul Manual Evidence Adjudication Workflow",
            "",
            "This workflow turns the `codex_pilot` review queues into independent adjudication records.",
            "",
            "## Inputs",
            "",
            *[f"- `{path}`" for path in payload["queue_paths"]],
            "",
            "## Template",
            "",
            f"- CSV template: `{payload['template_path']}`",
            f"- Rows: `{payload['rows']}`",
            "- Focused review packet: `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_PACKET.md`",
            "",
            "## Required Reviewer Fields",
            "",
            "- `final_vulnerable_side`: `A`, `B`, or `unclear`.",
            "- `label_status`: `confirmed_gold`, `corrected_side`, `ambiguous`, `insufficient_context`, or `not_security_relevant`.",
            "- `evidence_span_sufficient`: `yes`, `no`, `partial`, or `not_applicable`.",
            "- `final_evidence_window_ids`: selected visible window IDs when applicable.",
            "- `reviewer`, `reviewed_at`, and `rationale`: provenance and reasoning for the final decision.",
            "",
            "## Commands",
            "",
            "```powershell",
            ".\\.venv\\Scripts\\python.exe scripts\\export_manual_evidence_adjudication_template.py",
            ".\\.venv\\Scripts\\python.exe scripts\\render_manual_evidence_adjudication_packet.py",
            ".\\.venv\\Scripts\\python.exe scripts\\apply_manual_evidence_adjudications.py --dry-run",
            ".\\.venv\\Scripts\\python.exe scripts\\apply_manual_evidence_adjudications.py",
            ".\\.venv\\Scripts\\python.exe scripts\\analyze_manual_evidence_adjudications.py",
            "```",
            "",
            "Fill the reviewer fields in the CSV template before running the non-dry-run apply command.",
            "Treat the pilot annotation as a triage signal only. The adjudication output is the first artifact that can be treated as reviewer-confirmed.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    queue_rows = load_queue_rows(args.queues)
    template_rows = adjudication_template_rows(queue_rows)
    write_csv(ROOT / args.output, template_rows)
    payload = {
        "status": "ok",
        "queue_paths": args.queues,
        "template_path": args.output,
        "rows": len(template_rows),
        "queue_type_counts": {
            queue_type: sum(1 for row in queue_rows if row.get("queue_type") == queue_type)
            for queue_type in sorted({row.get("queue_type") for row in queue_rows})
        },
    }
    write_json(ROOT / args.summary_output, payload)
    report_path = ensure_parent(ROOT / args.report_output)
    report_path.write_text(render_report(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

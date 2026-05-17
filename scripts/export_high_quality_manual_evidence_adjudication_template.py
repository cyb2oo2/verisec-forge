from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scripts.export_manual_evidence_adjudication_template import load_queue_rows
from vrf.evidence_adjudication import adjudication_template_rows
from vrf.io_utils import ensure_parent, write_csv, write_json


QUEUE_PATH = "data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_v1.jsonl"
TEMPLATE_PATH = "data/processed/secure_code_primevul_manual_evidence_high_quality_adjudication_template_v1.csv"
SUMMARY_PATH = "reports/secure_code_primevul_manual_evidence_high_quality_adjudication_template_v1.json"
REPORT_PATH = "reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_WORKFLOW.md"


def build_payload(
    queue_rows: list[dict[str, Any]],
    *,
    queue_path: str = QUEUE_PATH,
    template_path: str = TEMPLATE_PATH,
) -> dict[str, Any]:
    return {
        "status": "ok",
        "scope": "high_quality_disagreement",
        "is_final_adjudication": False,
        "queue_path": queue_path,
        "template_path": template_path,
        "rows": len(queue_rows),
        "queue_type_counts": {
            queue_type: sum(1 for row in queue_rows if row.get("queue_type") == queue_type)
            for queue_type in sorted({row.get("queue_type") for row in queue_rows})
        },
        "requires_independent_review": True,
    }


def render_report(payload: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# PrimeVul High-Quality Evidence Adjudication Workflow",
            "",
            "This is the focused independent-review pass for the high-quality disagreement queue.",
            "It is intentionally narrower than the full 20-row adjudication template so the first reviewer pass can resolve the strongest evidence conflicts before moving to insufficient-context cases.",
            "",
            "## Scope",
            "",
            f"- Input queue: `{payload['queue_path']}`",
            f"- CSV template: `{payload['template_path']}`",
            "- Reviewer packet: `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_PACKET.md`",
            f"- Rows: `{payload['rows']}`",
            "- Final adjudication: `false` until the reviewer fields are completed and applied.",
            "",
            "## Required Reviewer Fields",
            "",
            "- `final_vulnerable_side`: `A`, `B`, or `unclear`.",
            "- `label_status`: `confirmed_gold`, `corrected_side`, `ambiguous`, `insufficient_context`, or `not_security_relevant`.",
            "- `evidence_span_sufficient`: `yes`, `no`, `partial`, or `not_applicable`.",
            "- `final_evidence_window_ids`: visible selected window IDs, such as `A1;B1`, when applicable.",
            "- `reviewer`, `reviewed_at`, and `rationale`: reviewer provenance and decision rationale.",
            "",
            "## Commands",
            "",
            "```powershell",
            ".\\.venv\\Scripts\\python.exe scripts\\export_high_quality_manual_evidence_adjudication_template.py",
            ".\\.venv\\Scripts\\python.exe scripts\\apply_manual_evidence_adjudications.py `",
            "  --queues data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_v1.jsonl `",
            "  --adjudications data/processed/secure_code_primevul_manual_evidence_high_quality_adjudication_template_v1.csv `",
            "  --output data/processed/secure_code_primevul_manual_evidence_high_quality_adjudicated_v1.jsonl `",
            "  --summary-output reports/secure_code_primevul_manual_evidence_high_quality_adjudication_apply_summary_v1.json `",
            "  --dry-run",
            ".\\.venv\\Scripts\\python.exe scripts\\apply_manual_evidence_adjudications.py `",
            "  --queues data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_v1.jsonl `",
            "  --adjudications data/processed/secure_code_primevul_manual_evidence_high_quality_adjudication_template_v1.csv `",
            "  --output data/processed/secure_code_primevul_manual_evidence_high_quality_adjudicated_v1.jsonl `",
            "  --summary-output reports/secure_code_primevul_manual_evidence_high_quality_adjudication_apply_summary_v1.json",
            ".\\.venv\\Scripts\\python.exe scripts\\analyze_manual_evidence_adjudications.py `",
            "  --input data/processed/secure_code_primevul_manual_evidence_high_quality_adjudicated_v1.jsonl `",
            "  --queues data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_v1.jsonl `",
            "  --json-output reports/secure_code_primevul_manual_evidence_high_quality_adjudication_analysis_v1.json `",
            "  --md-output reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_ANALYSIS.md",
            "```",
            "",
            "The empty template is not independent gold. It is only the review contract. Treat the `codex_pilot` and `codex_draft` fields as triage aids until a human reviewer completes the CSV and the apply step succeeds.",
            "",
        ]
    )


def main() -> int:
    queue_rows = load_queue_rows([QUEUE_PATH])
    template_rows = adjudication_template_rows(queue_rows)
    write_csv(ROOT / TEMPLATE_PATH, template_rows)
    payload = build_payload(queue_rows)
    write_json(ROOT / SUMMARY_PATH, payload)
    report_path = ensure_parent(ROOT / REPORT_PATH)
    report_path.write_text(render_report(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

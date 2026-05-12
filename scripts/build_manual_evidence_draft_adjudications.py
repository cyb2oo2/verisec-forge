from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import ensure_parent, read_jsonl, write_json, write_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build non-final codex_draft adjudication suggestions for high-quality evidence disagreements.",
    )
    parser.add_argument(
        "--queue",
        default="data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_v1.jsonl",
    )
    parser.add_argument(
        "--jsonl-output",
        default="data/processed/secure_code_primevul_manual_evidence_high_quality_codex_draft_adjudications_v1.jsonl",
    )
    parser.add_argument(
        "--json-output",
        default="reports/secure_code_primevul_manual_evidence_high_quality_codex_draft_adjudications_v1.json",
    )
    parser.add_argument(
        "--md-output",
        default="reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_DRAFT_ADJUDICATIONS.md",
    )
    return parser.parse_args()


def _draft_confidence(evidence_quality: int | None) -> str:
    if evidence_quality == 3:
        return "medium"
    if evidence_quality == 2:
        return "low"
    return "very_low"


def build_draft_adjudications(queue_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    drafts: list[dict[str, Any]] = []
    for row in sorted(queue_rows, key=lambda item: (item.get("priority", 99), item.get("audit_id", ""))):
        evidence_quality = row.get("evidence_quality")
        drafts.append(
            {
                "audit_id": row.get("audit_id"),
                "queue_type": row.get("queue_type"),
                "priority": row.get("priority"),
                "gold_vulnerable_side": row.get("gold_vulnerable_side"),
                "pilot_vulnerable_side": row.get("pilot_vulnerable_side"),
                "draft_final_vulnerable_side": row.get("pilot_vulnerable_side"),
                "draft_label_status": "candidate_corrected_side",
                "draft_evidence_span_sufficient": "partial",
                "draft_final_evidence_window_ids": row.get("selected_window_ids", []),
                "draft_confidence": _draft_confidence(evidence_quality),
                "draft_reviewer": "codex_draft",
                "draft_rationale": (
                    "Visible pilot-selected evidence conflicts with the stored gold vulnerable side; "
                    "requires independent reviewer confirmation before becoming final adjudication."
                ),
                "pilot_note": row.get("notes", ""),
                "review_action": row.get("review_action"),
            }
        )
    return drafts


def summarize_drafts(drafts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "status": "ok",
        "rows": len(drafts),
        "draft_reviewer": "codex_draft",
        "is_final_adjudication": False,
        "draft_label_status_counts": dict(sorted(Counter(row["draft_label_status"] for row in drafts).items())),
        "draft_confidence_counts": dict(sorted(Counter(row["draft_confidence"] for row in drafts).items())),
        "caveat": "These suggestions are non-final triage aids and must not be used as independent human adjudication.",
    }


def render_report(drafts: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul High-Quality Draft Adjudications",
        "",
        "These are `codex_draft` suggestions for reviewer convenience only. They are not independent human adjudications.",
        "",
        f"- Rows: `{summary['rows']}`",
        f"- Final adjudication: `{summary['is_final_adjudication']}`",
        f"- Caveat: {summary['caveat']}",
        "",
        "## Draft Summary",
        "",
        *[f"- Confidence `{key}`: `{value}`" for key, value in sorted(summary["draft_confidence_counts"].items())],
        "",
        "## Draft Rows",
        "",
    ]
    for row in drafts:
        lines.append(
            f"- `{row['audit_id']}`: gold=`{row['gold_vulnerable_side']}`, "
            f"draft_side=`{row['draft_final_vulnerable_side']}`, "
            f"confidence=`{row['draft_confidence']}`, windows=`{';'.join(row['draft_final_evidence_window_ids'])}`"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    queue_rows = read_jsonl(ROOT / args.queue)
    drafts = build_draft_adjudications(queue_rows)
    summary = summarize_drafts(drafts)
    write_jsonl(ROOT / args.jsonl_output, drafts)
    write_json(ROOT / args.json_output, {**summary, "drafts": drafts})
    md_path = ensure_parent(ROOT / args.md_output)
    md_path.write_text(render_report(drafts, summary), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

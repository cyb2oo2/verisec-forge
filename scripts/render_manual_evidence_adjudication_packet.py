from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.evidence_audit import render_manual_evidence_review_packet
from vrf.io_utils import ensure_parent, read_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render a focused adjudication packet for manual evidence review queues.",
    )
    parser.add_argument(
        "--audit-input",
        default="data/processed/secure_code_primevul_manual_evidence_audit_v1.jsonl",
    )
    parser.add_argument(
        "--queue",
        default="data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_v1.jsonl",
    )
    parser.add_argument(
        "--output",
        default="reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_PACKET.md",
    )
    return parser.parse_args()


def _queue_context_lines(queue_rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "# PrimeVul High-Quality Evidence Adjudication Packet",
        "",
        "This packet is for independent review of high-quality `codex_pilot` disagreements.",
        "The reviewer should decide whether the stored gold side, pilot side, or pair orientation is wrong.",
        "",
        "## Adjudication Instructions",
        "",
        "- Do not treat the pilot side as final; use it only as a triage hypothesis.",
        "- Inspect the highlighted windows first, then wider context if needed.",
        "- Fill the adjudication CSV with `final_vulnerable_side`, `label_status`, `evidence_span_sufficient`, `final_evidence_window_ids`, `reviewer`, `reviewed_at`, and `rationale`.",
        "- If the visible windows are insufficient, set `evidence_span_sufficient=partial` or `no` rather than guessing.",
        "",
        "## Queue Summary",
        "",
        f"- Rows: `{len(queue_rows)}`",
        "",
    ]
    for index, row in enumerate(queue_rows, start=1):
        lines.append(
            f"- Item {index}: priority=`{row.get('priority')}`, gold=`{row.get('gold_vulnerable_side')}`, "
            f"pilot=`{row.get('pilot_vulnerable_side')}`, q=`{row.get('evidence_quality')}`, "
            f"selected_windows=`{';'.join(row.get('selected_window_ids', []))}`"
        )
    lines.extend(["", "---", ""])
    return lines


def _inject_queue_context(packet: str, queue_rows: list[dict[str, Any]]) -> str:
    by_audit_id = {row["audit_id"]: row for row in queue_rows}
    lines: list[str] = []
    in_annotation_block = False
    for line in packet.splitlines():
        if line.startswith("# PrimeVul Manual Evidence Review Packet") or line.startswith("Use this packet"):
            continue
        if line.startswith("Annotation fields:"):
            in_annotation_block = True
            continue
        if line.startswith("## Item "):
            in_annotation_block = False
        if line.startswith("### Annotation Block"):
            in_annotation_block = True
            continue
        if in_annotation_block:
            if line.startswith("### Side A"):
                in_annotation_block = False
            else:
                continue
        lines.append(line)
        if line.startswith("## Item "):
            audit_id = line.split("`", 2)[1]
            queue_row = by_audit_id.get(audit_id)
            if queue_row:
                lines.extend(
                    [
                        "",
                        "### Adjudication Context",
                        "",
                        f"- Queue type: `{queue_row.get('queue_type')}`",
                        f"- Priority: `{queue_row.get('priority')}`",
                        f"- Review action: `{queue_row.get('review_action')}`",
                        f"- Gold vulnerable side: `{queue_row.get('gold_vulnerable_side')}`",
                        f"- Pilot vulnerable side: `{queue_row.get('pilot_vulnerable_side')}`",
                        f"- Pilot evidence side: `{queue_row.get('evidence_side')}`",
                        f"- Pilot evidence quality: `{queue_row.get('evidence_quality')}`",
                        f"- Pilot selected windows: `{';'.join(queue_row.get('selected_window_ids', []))}`",
                        f"- Reason: `{queue_row.get('reason')}`",
                        f"- Pilot note: `{queue_row.get('notes')}`",
                        "",
                        "Reviewer decision block:",
                        "",
                        "```yaml",
                        "final_vulnerable_side: ",
                        "label_status: ",
                        "evidence_span_sufficient: ",
                        "final_evidence_window_ids: []",
                        "reviewer: ",
                        "reviewed_at: ",
                        "rationale: ",
                        "```",
                        "",
                    ]
                )
    return "\n".join(lines) + "\n"


def render_packet(audit_rows: list[dict[str, Any]], queue_rows: list[dict[str, Any]]) -> str:
    by_audit_id = {row["audit_id"]: row for row in audit_rows}
    selected_rows = [by_audit_id[row["audit_id"]] for row in queue_rows if row.get("audit_id") in by_audit_id]
    packet = render_manual_evidence_review_packet(selected_rows, include_labels=True)
    return "\n".join(_queue_context_lines(queue_rows)) + _inject_queue_context(packet, queue_rows)


def main() -> int:
    args = parse_args()
    audit_rows = read_jsonl(ROOT / args.audit_input)
    queue_rows = read_jsonl(ROOT / args.queue)
    output = ensure_parent(ROOT / args.output)
    output.write_text(render_packet(audit_rows, queue_rows), encoding="utf-8")
    print(f"wrote {args.output} rows={len(queue_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

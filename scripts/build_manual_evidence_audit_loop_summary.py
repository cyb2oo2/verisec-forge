from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import ensure_parent, read_json, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a one-page evidence audit loop summary from run artifacts.",
    )
    parser.add_argument(
        "--pilot-findings",
        default="reports/secure_code_primevul_manual_evidence_pilot_findings_v1.json",
    )
    parser.add_argument(
        "--adjudication-analysis",
        default="reports/secure_code_primevul_manual_evidence_adjudication_analysis_v1.json",
    )
    parser.add_argument(
        "--draft-adjudications",
        default="reports/secure_code_primevul_manual_evidence_high_quality_codex_draft_adjudications_v1.json",
    )
    parser.add_argument(
        "--json-output",
        default="reports/secure_code_primevul_manual_evidence_audit_loop_summary_v1.json",
    )
    parser.add_argument(
        "--md-output",
        default="reports/PRIMEVUL_MANUAL_EVIDENCE_AUDIT_LOOP.md",
    )
    parser.add_argument(
        "--svg-output",
        default="reports/assets/primevul_manual_evidence_audit_loop.svg",
    )
    return parser.parse_args()


def build_payload(pilot: dict[str, Any], adjudication: dict[str, Any], draft: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "ok",
        "pilot_rows": pilot["completed_annotations"],
        "pilot_agreement_match": pilot["agreement_counts"].get("match", 0),
        "pilot_agreement_mismatch": pilot["agreement_counts"].get("mismatch", 0),
        "pilot_agreement_rate": pilot["agreement_rate"],
        "high_quality_disagreements": pilot["high_quality_disagreement_count"],
        "insufficient_context_cases": pilot["insufficient_context_count"],
        "draft_rows": draft["rows"],
        "draft_is_final_adjudication": draft["is_final_adjudication"],
        "completed_adjudications": adjudication["completed_adjudications"],
        "adjudication_completion_rate": adjudication["completion_rate"],
        "artifact_links": {
            "pilot_findings": "reports/PRIMEVUL_MANUAL_EVIDENCE_PILOT_FINDINGS.md",
            "review_queues": "reports/PRIMEVUL_MANUAL_EVIDENCE_REVIEW_QUEUES.md",
            "adjudication_workflow": "reports/PRIMEVUL_MANUAL_EVIDENCE_ADJUDICATION_WORKFLOW.md",
            "high_quality_packet": "reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_PACKET.md",
            "draft_adjudications": "reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_DRAFT_ADJUDICATIONS.md",
        },
        "interpretation": [
            "Pseudo-localization produces hard cases, not final evidence labels.",
            "codex_pilot review completed all 42 rows but agrees with stored gold only about half the time.",
            "The useful outputs are review queues: 6 high-quality disagreements and 14 insufficient-context cases.",
            "codex_draft suggestions are non-final triage aids; final labels require independent adjudication.",
        ],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    def report_link(path: str) -> str:
        return path.removeprefix("reports/")

    return "\n".join(
        [
            "# PrimeVul Manual Evidence Audit Loop",
            "",
            "This one-page summary shows how the evidence line moves from pseudo-localization to reviewer-confirmed labels.",
            "",
            "![Manual evidence audit loop](assets/primevul_manual_evidence_audit_loop.svg)",
            "",
            "## Loop Snapshot",
            "",
            f"- Pilot audit rows: `{payload['pilot_rows']}`",
            f"- Pilot/gold agreement: `{payload['pilot_agreement_match']}` match / `{payload['pilot_agreement_mismatch']}` mismatch",
            f"- Agreement rate: `{payload['pilot_agreement_rate']}`",
            f"- High-quality disagreement queue: `{payload['high_quality_disagreements']}` rows",
            f"- Insufficient-context queue: `{payload['insufficient_context_cases']}` rows",
            f"- Non-final `codex_draft` suggestions: `{payload['draft_rows']}` rows",
            f"- Completed independent adjudications: `{payload['completed_adjudications']}`",
            "",
            "## Stage Table",
            "",
            "| Stage | Artifact | Current Status |",
            "| --- | --- | --- |",
            "| Pseudo-localization | Hunk/window evidence candidates | Diagnostic only |",
            "| Pilot review | `codex_pilot` annotations | Complete over `42/42`; not human gold |",
            "| Queue construction | High-quality disagreement and insufficient-context JSONL | `6 + 14` rows materialized |",
            "| Reviewer workflow | CSV template plus focused packet | Ready for independent adjudication |",
            "| Draft suggestions | `codex_draft` suggestions | `6` non-final triage hints |",
            "| Final labels | Adjudicated queue JSONL | `0` completed so far |",
            "",
            "## Key Boundary",
            "",
            "`codex_pilot` and `codex_draft` are triage artifacts. The first reviewer-confirmed artifact begins only after the adjudication CSV is filled and applied.",
            "",
            "## Links",
            "",
            *[
                f"- [{name.replace('_', ' ').title()}]({report_link(path)})"
                for name, path in payload["artifact_links"].items()
            ],
            "",
        ]
    )


def render_svg(payload: dict[str, Any]) -> str:
    width = 1180
    height = 520
    stages = [
        ("Pseudo-localizer", "hunk/window\ncandidates", "#d7efe8"),
        ("Pilot audit", f"{payload['pilot_rows']} rows\n22/20 split", "#f7e4c6"),
        ("Review queues", f"{payload['high_quality_disagreements']} HQ + {payload['insufficient_context_cases']} context", "#dfe6ff"),
        ("Adjudication", "CSV + packet\nready", "#eadcf8"),
        ("Final labels", f"{payload['completed_adjudications']} complete", "#f2d6d6"),
    ]
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="PrimeVul manual evidence audit loop">',
        '<rect width="1180" height="520" fill="#fbfaf7"/>',
        '<text x="40" y="52" font-family="Georgia, serif" font-size="30" font-weight="700" fill="#1f2933">PrimeVul Manual Evidence Audit Loop</text>',
        '<text x="40" y="84" font-family="Verdana, sans-serif" font-size="15" fill="#52606d">Triage artifacts stay separate from reviewer-confirmed adjudication.</text>',
    ]
    box_w = 190
    box_h = 140
    y = 155
    for index, (title, subtitle, fill) in enumerate(stages):
        x = 40 + index * 225
        lines.append(f'<rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="18" fill="{fill}" stroke="#243b53" stroke-width="1.5"/>')
        lines.append(f'<text x="{x + 18}" y="{y + 40}" font-family="Verdana, sans-serif" font-size="18" font-weight="700" fill="#102a43">{title}</text>')
        subtitle_parts = subtitle.splitlines()
        lines.append(f'<text x="{x + 18}" y="{y + 78}" font-family="Verdana, sans-serif" font-size="15" fill="#334e68">')
        for offset, part in enumerate(subtitle_parts):
            dy = 0 if offset == 0 else 24
            lines.append(f'<tspan x="{x + 18}" dy="{dy}">{part}</tspan>')
        lines.append("</text>")
        if index < len(stages) - 1:
            arrow_x = x + box_w + 12
            lines.append(f'<line x1="{arrow_x}" y1="{y + 70}" x2="{arrow_x + 42}" y2="{y + 70}" stroke="#486581" stroke-width="3"/>')
            lines.append(f'<polygon points="{arrow_x + 42},{y + 70} {arrow_x + 30},{y + 62} {arrow_x + 30},{y + 78}" fill="#486581"/>')
    lines.extend(
        [
            '<rect x="40" y="360" width="1100" height="92" rx="16" fill="#ffffff" stroke="#bcccdc"/>',
            '<text x="62" y="392" font-family="Verdana, sans-serif" font-size="17" font-weight="700" fill="#102a43">Current boundary</text>',
            '<text x="62" y="424" font-family="Verdana, sans-serif" font-size="15" fill="#334e68">codex_pilot and codex_draft are triage signals only; final labels require independent adjudication.</text>',
            f'<text x="62" y="448" font-family="Verdana, sans-serif" font-size="15" fill="#334e68">Pilot agreement: {payload["pilot_agreement_match"]} match / {payload["pilot_agreement_mismatch"]} mismatch. Reviewer-confirmed labels: {payload["completed_adjudications"]}.</text>',
            "</svg>",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    pilot = read_json(ROOT / args.pilot_findings)
    adjudication = read_json(ROOT / args.adjudication_analysis)
    draft = read_json(ROOT / args.draft_adjudications)
    payload = build_payload(pilot, adjudication, draft)
    write_json(ROOT / args.json_output, payload)
    md_path = ensure_parent(ROOT / args.md_output)
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    svg_path = ensure_parent(ROOT / args.svg_output)
    svg_path.write_text(render_svg(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

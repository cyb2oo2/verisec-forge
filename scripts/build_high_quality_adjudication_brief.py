from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import ensure_parent, read_jsonl, write_json


AUDIT_INPUT = "data/processed/secure_code_primevul_manual_evidence_audit_v1.jsonl"
QUEUE_INPUT = "data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_v1.jsonl"
JSON_OUTPUT = "reports/secure_code_primevul_manual_evidence_high_quality_adjudication_brief_v1.json"
MD_OUTPUT = "reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_BRIEF.md"


def _side_key(side: str) -> str:
    return "side_a" if side == "A" else "side_b"


def _find_window(audit_row: dict[str, Any], window_id: str) -> dict[str, Any]:
    if not window_id:
        return {}
    side = window_id[0]
    windows = audit_row.get(_side_key(side), {}).get("windows", [])
    for window in windows:
        if window.get("window_id") == window_id:
            return window
    return {}


def _window_summary(window: dict[str, Any]) -> dict[str, Any]:
    return {
        "window_id": window.get("window_id", ""),
        "header": window.get("header", ""),
        "direction_labels": window.get("direction_labels", []),
        "risk_support": window.get("risk_support", 0),
        "safety_support": window.get("safety_support", 0),
        "removed_preview": window.get("removed_preview", []),
        "added_preview": window.get("added_preview", []),
    }


def _side_probability(audit_row: dict[str, Any], side: str) -> float | None:
    value = audit_row.get(_side_key(side), {}).get("detector_probability")
    return float(value) if value is not None else None


def build_case_briefs(
    audit_rows: list[dict[str, Any]],
    queue_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    audit_by_id = {row["audit_id"]: row for row in audit_rows}
    cases: list[dict[str, Any]] = []
    missing_audit_ids: list[str] = []

    for index, queue_row in enumerate(queue_rows, start=1):
        audit_id = str(queue_row["audit_id"])
        audit_row = audit_by_id.get(audit_id)
        if not audit_row:
            missing_audit_ids.append(audit_id)
            continue

        selected_window_ids = list(queue_row.get("selected_window_ids", []))
        selected_windows = [_window_summary(_find_window(audit_row, window_id)) for window_id in selected_window_ids]
        gold_side = str(queue_row.get("gold_vulnerable_side", ""))
        pilot_side = str(queue_row.get("pilot_vulnerable_side", ""))
        model_side = str(queue_row.get("model_vulnerable_side", ""))

        cases.append(
            {
                "case_index": index,
                "audit_id": audit_id,
                "pair_key": queue_row.get("pair_key"),
                "project": audit_row.get("project"),
                "cve": audit_row.get("cve"),
                "changed_line_bucket": queue_row.get("changed_line_bucket"),
                "priority": queue_row.get("priority"),
                "source_pool": queue_row.get("source_pool"),
                "gold_vulnerable_side": gold_side,
                "pilot_vulnerable_side": pilot_side,
                "model_vulnerable_side": model_side,
                "pilot_evidence_side": queue_row.get("evidence_side"),
                "pilot_evidence_quality": queue_row.get("evidence_quality"),
                "selected_window_ids": selected_window_ids,
                "selected_windows": selected_windows,
                "pilot_note": queue_row.get("notes"),
                "reason": queue_row.get("reason"),
                "side_probabilities": {
                    "A": _side_probability(audit_row, "A"),
                    "B": _side_probability(audit_row, "B"),
                },
                "decision_questions": [
                    f"Does the selected evidence support side {pilot_side} over stored gold side {gold_side}?",
                    "Is the visible evidence span sufficient, or does this case require wider context?",
                    "Should the final label be confirmed_gold, corrected_side, ambiguous, insufficient_context, or not_security_relevant?",
                ],
            }
        )

    return {
        "status": "ok" if not missing_audit_ids else "missing_audit_rows",
        "scope": "high_quality_disagreement_adjudication_brief",
        "is_final_adjudication": False,
        "rows": len(cases),
        "missing_audit_ids": missing_audit_ids,
        "gold_pilot_conflicts": sum(
            1 for case in cases if case["gold_vulnerable_side"] != case["pilot_vulnerable_side"]
        ),
        "model_pilot_conflicts": sum(
            1 for case in cases if case["model_vulnerable_side"] != case["pilot_vulnerable_side"]
        ),
        "cases": cases,
    }


def _preview_lines(lines: list[str]) -> list[str]:
    if not lines:
        return ["  - None."]
    return [f"  - `{line}`" for line in lines[:4]]


def render_report(payload: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul High-Quality Adjudication Brief",
        "",
        "This brief summarizes the `6` high-quality pilot/gold disagreement cases before independent adjudication.",
        "It is not a final label artifact; it is a compact reviewer guide for filling the focused adjudication CSV.",
        "",
        "## Summary",
        "",
        f"- Cases: `{payload['rows']}`",
        f"- Gold/pilot conflicts: `{payload['gold_pilot_conflicts']}`",
        f"- Model/pilot conflicts: `{payload['model_pilot_conflicts']}`",
        f"- Final adjudication: `{str(payload['is_final_adjudication']).lower()}`",
        "",
    ]

    for case in payload["cases"]:
        lines.extend(
            [
                f"## Case {case['case_index']}: `{case['audit_id']}`",
                "",
                f"- Pair key: `{case['pair_key']}`",
                f"- Project/CVE: `{case['project']}` / `{case['cve']}`",
                f"- Bucket/source: `{case['changed_line_bucket']}` / `{case['source_pool']}`",
                f"- Gold/Pilot/Model vulnerable side: `{case['gold_vulnerable_side']}` / `{case['pilot_vulnerable_side']}` / `{case['model_vulnerable_side']}`",
                f"- Pilot evidence side/quality: `{case['pilot_evidence_side']}` / `{case['pilot_evidence_quality']}`",
                f"- Side probabilities: A=`{case['side_probabilities']['A']}`, B=`{case['side_probabilities']['B']}`",
                f"- Pilot note: {case['pilot_note']}",
                "",
                "Reviewer questions:",
                "",
                *[f"- {question}" for question in case["decision_questions"]],
                "",
                "Selected evidence windows:",
                "",
            ]
        )
        for window in case["selected_windows"]:
            lines.extend(
                [
                    f"### Window `{window['window_id']}`",
                    "",
                    f"- Header: `{window['header']}`",
                    f"- Direction labels: `{','.join(window['direction_labels'])}`",
                    f"- Risk/safety support: `{window['risk_support']}` / `{window['safety_support']}`",
                    "",
                    "Removed preview:",
                    "",
                    *_preview_lines(window["removed_preview"]),
                    "",
                    "Added preview:",
                    "",
                    *_preview_lines(window["added_preview"]),
                    "",
                ]
            )
    lines.extend(
        [
            "## Next Step",
            "",
            "Fill `data/processed/secure_code_primevul_manual_evidence_high_quality_adjudication_template_v1.csv`, then run the dry-run apply command from `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_WORKFLOW.md` before writing adjudicated JSONL.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    audit_rows = read_jsonl(ROOT / AUDIT_INPUT)
    queue_rows = read_jsonl(ROOT / QUEUE_INPUT)
    payload = build_case_briefs(audit_rows, queue_rows)
    write_json(ROOT / JSON_OUTPUT, payload)
    md_path = ensure_parent(ROOT / MD_OUTPUT)
    md_path.write_text(render_report(payload), encoding="utf-8")
    print(json.dumps({key: value for key, value in payload.items() if key != "cases"}, indent=2, ensure_ascii=False))
    return 0 if payload["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

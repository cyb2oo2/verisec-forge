from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import ensure_parent, read_jsonl, write_json


AUDIT_INPUT = "data/processed/secure_code_primevul_manual_evidence_audit_v1.jsonl"
QUEUE_INPUT = "data/processed/secure_code_primevul_manual_evidence_insufficient_context_v1.jsonl"
JSON_OUTPUT = "reports/secure_code_primevul_manual_evidence_insufficient_context_brief_v1.json"
MD_OUTPUT = "reports/PRIMEVUL_MANUAL_EVIDENCE_INSUFFICIENT_CONTEXT_BRIEF.md"


def _side_key(side: str) -> str:
    return "side_a" if side == "A" else "side_b"


def _side_probability(audit_row: dict[str, Any], side: str) -> float | None:
    value = audit_row.get(_side_key(side), {}).get("detector_probability")
    return float(value) if value is not None else None


def _find_window(audit_row: dict[str, Any], window_id: str) -> dict[str, Any]:
    if not window_id:
        return {}
    side = window_id[0]
    for window in audit_row.get(_side_key(side), {}).get("windows", []):
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


def _context_requests(queue_row: dict[str, Any]) -> list[str]:
    evidence_side = queue_row.get("evidence_side")
    bucket = queue_row.get("changed_line_bucket")
    requests = [
        "Inspect the full changed hunk around each selected window.",
        "Check whether the removed lines or added lines contain the actual vulnerable behavior.",
    ]
    if evidence_side in {"both", "unclear"}:
        requests.append("Compare both sides before choosing a final vulnerable side; current evidence is mixed.")
    if bucket == "26+":
        requests.append("Review surrounding control flow because this is a large-diff case.")
    requests.append("If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.")
    return requests


def build_context_brief(
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
                "gold_vulnerable_side": queue_row.get("gold_vulnerable_side"),
                "model_vulnerable_side": queue_row.get("model_vulnerable_side"),
                "pilot_evidence_side": queue_row.get("evidence_side"),
                "pilot_evidence_quality": queue_row.get("evidence_quality"),
                "selected_window_ids": selected_window_ids,
                "selected_windows": selected_windows,
                "pilot_note": queue_row.get("notes"),
                "reason": queue_row.get("reason"),
                "review_action": queue_row.get("review_action"),
                "side_probabilities": {
                    "A": _side_probability(audit_row, "A"),
                    "B": _side_probability(audit_row, "B"),
                },
                "context_requests": _context_requests(queue_row),
            }
        )

    bucket_counts = Counter(case["changed_line_bucket"] for case in cases)
    evidence_side_counts = Counter(case["pilot_evidence_side"] for case in cases)
    source_pool_counts = Counter(case["source_pool"] for case in cases)
    return {
        "status": "ok" if not missing_audit_ids else "missing_audit_rows",
        "scope": "insufficient_context_wider_review_brief",
        "is_final_adjudication": False,
        "rows": len(cases),
        "missing_audit_ids": missing_audit_ids,
        "bucket_counts": dict(sorted(bucket_counts.items())),
        "evidence_side_counts": dict(sorted(evidence_side_counts.items())),
        "source_pool_counts": dict(sorted(source_pool_counts.items())),
        "cases": cases,
    }


def _preview_lines(lines: list[str]) -> list[str]:
    if not lines:
        return ["  - None."]
    return [f"  - `{line}`" for line in lines[:4]]


def render_report(payload: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Insufficient-Context Review Brief",
        "",
        "This brief summarizes the insufficient-context manual evidence queue for wider-context review.",
        "It is not a final label artifact. Its purpose is to identify where the hunk/window evidence is too narrow for reliable adjudication.",
        "",
        "## Summary",
        "",
        f"- Cases: `{payload['rows']}`",
        f"- Final adjudication: `{str(payload['is_final_adjudication']).lower()}`",
        f"- Bucket counts: `{payload['bucket_counts']}`",
        f"- Pilot evidence-side counts: `{payload['evidence_side_counts']}`",
        f"- Source-pool counts: `{payload['source_pool_counts']}`",
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
                f"- Gold/model vulnerable side: `{case['gold_vulnerable_side']}` / `{case['model_vulnerable_side']}`",
                f"- Pilot evidence side/quality: `{case['pilot_evidence_side']}` / `{case['pilot_evidence_quality']}`",
                f"- Side probabilities: A=`{case['side_probabilities']['A']}`, B=`{case['side_probabilities']['B']}`",
                f"- Reason: {case['reason']}",
                f"- Pilot note: {case['pilot_note']}",
                "",
                "Wider-context requests:",
                "",
                *[f"- {request}" for request in case["context_requests"]],
                "",
                "Selected narrow evidence windows:",
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
            "Use this brief to decide whether the existing selected windows can be expanded into sufficient evidence spans. If not, keep the row marked as insufficient context rather than forcing a vulnerable-side decision.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    audit_rows = read_jsonl(ROOT / AUDIT_INPUT)
    queue_rows = read_jsonl(ROOT / QUEUE_INPUT)
    payload = build_context_brief(audit_rows, queue_rows)
    write_json(ROOT / JSON_OUTPUT, payload)
    md_path = ensure_parent(ROOT / MD_OUTPUT)
    md_path.write_text(render_report(payload), encoding="utf-8")
    print(json.dumps({key: value for key, value in payload.items() if key != "cases"}, indent=2, ensure_ascii=False))
    return 0 if payload["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

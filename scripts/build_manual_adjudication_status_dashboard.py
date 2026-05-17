from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import ensure_parent, read_json, write_json


HIGH_QUALITY_TEMPLATE_SUMMARY = "reports/secure_code_primevul_manual_evidence_high_quality_adjudication_template_v1.json"
HIGH_QUALITY_APPLY_SUMMARY = "reports/secure_code_primevul_manual_evidence_high_quality_adjudication_apply_summary_v1.json"
HIGH_QUALITY_BRIEF = "reports/secure_code_primevul_manual_evidence_high_quality_adjudication_brief_v1.json"
INSUFFICIENT_CONTEXT_BRIEF = "reports/secure_code_primevul_manual_evidence_insufficient_context_brief_v1.json"
JSON_OUTPUT = "reports/secure_code_primevul_manual_adjudication_status_dashboard_v1.json"
MD_OUTPUT = "reports/PRIMEVUL_MANUAL_ADJUDICATION_STATUS_DASHBOARD.md"


def _safe_read_json(path: str) -> dict[str, Any]:
    full_path = ROOT / path
    if not full_path.exists():
        return {"status": "missing", "path": path}
    payload = read_json(full_path)
    payload["_path"] = path
    return payload


def _track_status(rows: int, completed: int, *, dry_run: bool = False) -> str:
    if rows == 0:
        return "empty"
    if completed == 0:
        return "not_started_dry_run" if dry_run else "not_started"
    if completed < rows:
        return "in_progress_dry_run" if dry_run else "in_progress"
    return "complete_dry_run" if dry_run else "complete"


def build_dashboard(
    high_quality_template: dict[str, Any],
    high_quality_apply: dict[str, Any],
    high_quality_brief: dict[str, Any],
    insufficient_context_brief: dict[str, Any],
) -> dict[str, Any]:
    high_quality_rows = int(high_quality_template.get("rows", high_quality_brief.get("rows", 0)))
    high_quality_completed = int(high_quality_apply.get("updated", 0))
    high_quality_dry_run = bool(high_quality_apply.get("dry_run", False))
    insufficient_rows = int(insufficient_context_brief.get("rows", 0))

    tracks = [
        {
            "track": "high_quality_disagreement",
            "purpose": "Resolve strongest pilot/gold evidence conflicts.",
            "rows": high_quality_rows,
            "completed": high_quality_completed,
            "completion_rate": round(high_quality_completed / high_quality_rows, 4)
            if high_quality_rows
            else 0.0,
            "status": _track_status(high_quality_rows, high_quality_completed, dry_run=high_quality_dry_run),
            "dry_run": high_quality_dry_run,
            "blocked_by": "independent reviewer fields are blank"
            if high_quality_completed == 0
            else "",
            "primary_artifacts": [
                "data/processed/secure_code_primevul_manual_evidence_high_quality_adjudication_template_v1.csv",
                "reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_WORKFLOW.md",
                "reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_BRIEF.md",
                "reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_PACKET.md",
            ],
            "next_action": "Fill the focused CSV, rerun apply with --dry-run, then apply without --dry-run.",
            "diagnostics": {
                "gold_pilot_conflicts": high_quality_brief.get("gold_pilot_conflicts", 0),
                "model_pilot_conflicts": high_quality_brief.get("model_pilot_conflicts", 0),
                "apply_errors": high_quality_apply.get("errors", []),
                "skipped_blank": high_quality_apply.get("skipped_blank", 0),
            },
        },
        {
            "track": "insufficient_context",
            "purpose": "Decide whether narrow hunk/window evidence needs wider context.",
            "rows": insufficient_rows,
            "completed": 0,
            "completion_rate": 0.0,
            "status": "review_packet_ready",
            "dry_run": False,
            "blocked_by": "requires wider-context inspection before final side labels",
            "primary_artifacts": [
                "data/processed/secure_code_primevul_manual_evidence_insufficient_context_v1.jsonl",
                "reports/PRIMEVUL_MANUAL_EVIDENCE_INSUFFICIENT_CONTEXT_BRIEF.md",
            ],
            "next_action": "Inspect wider context for each row; keep insufficient_context when evidence remains ambiguous.",
            "diagnostics": {
                "bucket_counts": insufficient_context_brief.get("bucket_counts", {}),
                "evidence_side_counts": insufficient_context_brief.get("evidence_side_counts", {}),
                "source_pool_counts": insufficient_context_brief.get("source_pool_counts", {}),
            },
        },
    ]
    total_rows = sum(track["rows"] for track in tracks)
    total_completed = sum(track["completed"] for track in tracks)
    return {
        "status": "ok",
        "scope": "manual_adjudication_status_dashboard",
        "is_final_adjudication": False,
        "total_rows": total_rows,
        "total_completed": total_completed,
        "overall_completion_rate": round(total_completed / total_rows, 4) if total_rows else 0.0,
        "tracks": tracks,
        "next_research_gate": "Reviewer-confirmed labels begin only after non-dry-run apply writes adjudicated JSONL.",
    }


def _artifact_lines(paths: list[str]) -> list[str]:
    return [f"  - `{path}`" for path in paths]


def _format_mapping(mapping: dict[str, Any]) -> str:
    if not mapping:
        return "`{}`"
    return "`" + ", ".join(f"{key}: {value}" for key, value in sorted(mapping.items())) + "`"


def render_report(payload: dict[str, Any]) -> str:
    lines = [
        "# PrimeVul Manual Adjudication Status Dashboard",
        "",
        "This dashboard summarizes the current manual evidence adjudication state.",
        "It is not a final adjudication artifact; it tracks what is ready, blocked, or still awaiting reviewer action.",
        "",
        "## Summary",
        "",
        f"- Total rows: `{payload['total_rows']}`",
        f"- Completed rows: `{payload['total_completed']}`",
        f"- Overall completion rate: `{payload['overall_completion_rate']}`",
        f"- Final adjudication: `{str(payload['is_final_adjudication']).lower()}`",
        f"- Research gate: {payload['next_research_gate']}",
        "",
        "## Track Status",
        "",
        "| Track | Rows | Completed | Completion | Status | Blocked By | Next Action |",
        "| --- | ---: | ---: | ---: | --- | --- | --- |",
    ]
    for track in payload["tracks"]:
        lines.append(
            f"| `{track['track']}` | {track['rows']} | {track['completed']} | {track['completion_rate']} | "
            f"`{track['status']}` | {track['blocked_by']} | {track['next_action']} |"
        )

    for track in payload["tracks"]:
        lines.extend(
            [
                "",
                f"## {track['track']}",
                "",
                f"- Purpose: {track['purpose']}",
                f"- Dry run: `{str(track['dry_run']).lower()}`",
                "- Primary artifacts:",
                *_artifact_lines(track["primary_artifacts"]),
                "",
                "Diagnostics:",
                "",
            ]
        )
        diagnostics = track["diagnostics"]
        for key, value in diagnostics.items():
            if isinstance(value, dict):
                rendered = _format_mapping(value)
            else:
                rendered = f"`{value}`"
            lines.append(f"- `{key}`: {rendered}")
    lines.extend(
        [
            "",
            "## Next Step",
            "",
            "Complete the high-quality CSV first because it is the smallest reviewer-confirmed gate. Then use the insufficient-context brief to decide whether the current hunk/window packet needs wider code context before final labels are assigned.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    payload = build_dashboard(
        _safe_read_json(HIGH_QUALITY_TEMPLATE_SUMMARY),
        _safe_read_json(HIGH_QUALITY_APPLY_SUMMARY),
        _safe_read_json(HIGH_QUALITY_BRIEF),
        _safe_read_json(INSUFFICIENT_CONTEXT_BRIEF),
    )
    write_json(ROOT / JSON_OUTPUT, payload)
    md_path = ensure_parent(ROOT / MD_OUTPUT)
    md_path.write_text(render_report(payload), encoding="utf-8")
    print(json.dumps({key: value for key, value in payload.items() if key != "tracks"}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

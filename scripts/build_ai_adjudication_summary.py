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

from vrf.io_utils import ensure_parent, read_jsonl, write_csv, write_json


INPUTS = [
    "data/processed/secure_code_primevul_manual_evidence_high_quality_adjudicated_v1.jsonl",
    "data/processed/secure_code_primevul_manual_evidence_insufficient_context_ai_adjudicated_v1.jsonl",
]
CSV_OUTPUT = "reports/secure_code_primevul_ai_adjudication_summary_v1.csv"
JSON_OUTPUT = "reports/secure_code_primevul_ai_adjudication_summary_v1.json"
MD_OUTPUT = "reports/PRIMEVUL_AI_ADJUDICATION_SUMMARY.md"


def _is_ai_reviewer(reviewer: str) -> bool:
    return reviewer.startswith(("codex_", "ai_", "gpt_"))


def _summary_row(row: dict[str, Any]) -> dict[str, Any]:
    adjudication = row.get("adjudication", {})
    return {
        "audit_id": row.get("audit_id", ""),
        "queue_type": row.get("queue_type", ""),
        "project": str(row.get("pair_key", "")).split("|")[0] if row.get("pair_key") else "",
        "cve": str(row.get("pair_key", "")).split("|")[-1] if row.get("pair_key") else "",
        "changed_line_bucket": row.get("changed_line_bucket", ""),
        "source_pool": row.get("source_pool", ""),
        "gold_vulnerable_side": row.get("gold_vulnerable_side", ""),
        "model_vulnerable_side": row.get("model_vulnerable_side", ""),
        "pilot_vulnerable_side": row.get("pilot_vulnerable_side", ""),
        "final_vulnerable_side": adjudication.get("final_vulnerable_side", ""),
        "label_status": adjudication.get("label_status", ""),
        "evidence_span_sufficient": adjudication.get("evidence_span_sufficient", ""),
        "final_evidence_window_ids": ";".join(adjudication.get("final_evidence_window_ids", [])),
        "reviewer": adjudication.get("reviewer", ""),
        "is_ai_filled": _is_ai_reviewer(str(adjudication.get("reviewer", ""))),
        "is_human_confirmed": not _is_ai_reviewer(str(adjudication.get("reviewer", "")))
        and bool(adjudication.get("reviewer")),
        "rationale": adjudication.get("rationale", ""),
    }


def build_summary(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    table_rows = [_summary_row(row) for row in rows]
    label_counts = Counter(row["label_status"] for row in table_rows)
    queue_label_counts: dict[str, Counter[str]] = {}
    evidence_counts = Counter(row["evidence_span_sufficient"] for row in table_rows)
    bucket_counts = Counter(row["changed_line_bucket"] for row in table_rows)
    corrected_by_project = Counter(
        row["project"] for row in table_rows if row["label_status"] == "corrected_side"
    )
    for row in table_rows:
        queue_label_counts.setdefault(str(row["queue_type"]), Counter())
        queue_label_counts[str(row["queue_type"])][str(row["label_status"])] += 1

    ai_filled = sum(1 for row in table_rows if row["is_ai_filled"])
    human_confirmed = sum(1 for row in table_rows if row["is_human_confirmed"])
    payload = {
        "status": "ok",
        "scope": "primevul_ai_adjudication_summary",
        "rows": len(table_rows),
        "ai_filled_rows": ai_filled,
        "human_confirmed_rows": human_confirmed,
        "is_final_human_gold": False,
        "label_status_counts": dict(sorted(label_counts.items())),
        "queue_label_status_counts": {
            queue: dict(sorted(counts.items()))
            for queue, counts in sorted(queue_label_counts.items())
        },
        "evidence_span_sufficiency_counts": dict(sorted(evidence_counts.items())),
        "changed_line_bucket_counts": dict(sorted(bucket_counts.items())),
        "corrected_side_project_counts": dict(sorted(corrected_by_project.items())),
        "csv_output": CSV_OUTPUT,
    }
    return table_rows, payload


def _mapping_lines(mapping: dict[str, Any]) -> list[str]:
    if not mapping:
        return ["- None."]
    return [f"- `{key}`: `{value}`" for key, value in mapping.items()]


def render_report(payload: dict[str, Any], table_rows: list[dict[str, Any]]) -> str:
    fully_human_confirmed = payload["rows"] > 0 and payload["human_confirmed_rows"] == payload["rows"]
    lines = [
        "# PrimeVul AI Adjudication Summary",
        "",
        "This report consolidates the adjudication pass over the high-quality disagreement and insufficient-context queues.",
        "Once every row carries a non-AI reviewer, it reports human-confirmed labels for "
        "this 20-row set; it is still not project-wide independent human gold."
        if fully_human_confirmed
        else "It is an AI audit draft, not independent human gold.",
        "",
        "## Summary",
        "",
        f"- Rows: `{payload['rows']}`",
        f"- AI-filled rows: `{payload['ai_filled_rows']}`",
        f"- Human-confirmed rows: `{payload['human_confirmed_rows']}`",
        f"- Final human gold: `{str(payload['is_final_human_gold']).lower()}`",
        f"- CSV table: `{payload['csv_output']}`",
        "",
        "## Label Status Counts",
        "",
        *_mapping_lines(payload["label_status_counts"]),
        "",
        "## By Queue",
        "",
    ]
    for queue, counts in payload["queue_label_status_counts"].items():
        rendered = ", ".join(f"{key}=`{value}`" for key, value in counts.items())
        lines.append(f"- `{queue}`: {rendered}")
    lines.extend(
        [
            "",
            "## Evidence Span Sufficiency",
            "",
            *_mapping_lines(payload["evidence_span_sufficiency_counts"]),
            "",
            "## Corrected-Side Cases",
            "",
            "| Queue | Project | CVE | Bucket | Final Side | Evidence | Rationale |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    corrected_rows = [row for row in table_rows if row["label_status"] == "corrected_side"]
    for row in corrected_rows:
        rationale = str(row["rationale"]).replace("|", "/")
        lines.append(
            f"| `{row['queue_type']}` | `{row['project']}` | `{row['cve']}` | `{row['changed_line_bucket']}` | "
            f"`{row['final_vulnerable_side']}` | `{row['evidence_span_sufficient']}` | {rationale} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "All 20 rows now carry a non-AI reviewer; the project may report these as reviewer-confirmed labels for this 20-row set, not as AI-filled adjudication."
            if fully_human_confirmed
            else "The AI pass resolves some high-signal conflicts, but the project should still report these rows as AI-filled adjudication rather than independent reviewer-confirmed labels.",
            "The large remaining `insufficient_context` count is useful: it shows that evidence-window localization often needs wider code context before a trustworthy final side label can be assigned.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    rows: list[dict[str, Any]] = []
    for path in INPUTS:
        rows.extend(read_jsonl(ROOT / path))
    table_rows, payload = build_summary(rows)
    write_csv(ROOT / CSV_OUTPUT, table_rows)
    write_json(ROOT / JSON_OUTPUT, payload)
    md_path = ensure_parent(ROOT / MD_OUTPUT)
    md_path.write_text(render_report(payload, table_rows), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

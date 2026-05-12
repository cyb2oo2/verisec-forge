from __future__ import annotations

from collections import Counter
from typing import Any

from vrf.evidence_audit import parse_window_ids


ADJUDICATION_FIELDS = [
    "audit_id",
    "queue_type",
    "priority",
    "review_action",
    "gold_vulnerable_side",
    "pilot_vulnerable_side",
    "evidence_quality",
    "selected_window_ids",
    "final_vulnerable_side",
    "label_status",
    "evidence_span_sufficient",
    "final_evidence_window_ids",
    "reviewer",
    "reviewed_at",
    "rationale",
]

VALID_FINAL_SIDES = {"A", "B", "unclear"}
VALID_LABEL_STATUSES = {
    "confirmed_gold",
    "corrected_side",
    "ambiguous",
    "insufficient_context",
    "not_security_relevant",
}
VALID_EVIDENCE_SPAN_SUFFICIENCY = {"yes", "no", "partial", "not_applicable"}


def adjudication_template_rows(queue_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in sorted(queue_rows, key=lambda item: (item.get("priority", 99), item.get("audit_id", ""))):
        rows.append(
            {
                "audit_id": row.get("audit_id"),
                "queue_type": row.get("queue_type"),
                "priority": row.get("priority"),
                "review_action": row.get("review_action"),
                "gold_vulnerable_side": row.get("gold_vulnerable_side"),
                "pilot_vulnerable_side": row.get("pilot_vulnerable_side"),
                "evidence_quality": row.get("evidence_quality"),
                "selected_window_ids": ";".join(row.get("selected_window_ids", [])),
                "final_vulnerable_side": "",
                "label_status": "",
                "evidence_span_sufficient": "",
                "final_evidence_window_ids": "",
                "reviewer": "",
                "reviewed_at": "",
                "rationale": "",
            }
        )
    return rows


def _valid_window_ids(row: dict[str, Any]) -> set[str]:
    return set(row.get("selected_window_ids", []))


def apply_adjudication_rows(
    queue_rows: list[dict[str, Any]],
    adjudication_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    by_audit_id = {row["audit_id"]: dict(row) for row in queue_rows}
    updated = 0
    skipped_blank = 0
    errors: list[dict[str, Any]] = []

    for adjudication in adjudication_rows:
        audit_id = adjudication.get("audit_id")
        if audit_id not in by_audit_id:
            errors.append({"audit_id": audit_id, "errors": ["unknown_audit_id"]})
            continue

        final_side = (adjudication.get("final_vulnerable_side") or "").strip()
        label_status = (adjudication.get("label_status") or "").strip()
        span_sufficient = (adjudication.get("evidence_span_sufficient") or "").strip()
        final_window_ids = parse_window_ids(adjudication.get("final_evidence_window_ids"))
        reviewer = adjudication.get("reviewer") or ""
        reviewed_at = adjudication.get("reviewed_at") or ""
        rationale = adjudication.get("rationale") or ""

        if not final_side and not label_status and not span_sufficient and not final_window_ids and not rationale:
            skipped_blank += 1
            continue

        row_errors: list[str] = []
        if final_side not in VALID_FINAL_SIDES:
            row_errors.append("final_vulnerable_side")
        if label_status not in VALID_LABEL_STATUSES:
            row_errors.append("label_status")
        if span_sufficient not in VALID_EVIDENCE_SPAN_SUFFICIENCY:
            row_errors.append("evidence_span_sufficient")

        invalid_window_ids = [
            window_id for window_id in final_window_ids if window_id not in _valid_window_ids(by_audit_id[audit_id])
        ]
        if invalid_window_ids:
            row_errors.append("final_evidence_window_ids")

        if row_errors:
            errors.append(
                {
                    "audit_id": audit_id,
                    "errors": row_errors,
                    "invalid_window_ids": invalid_window_ids,
                }
            )
            continue

        by_audit_id[audit_id]["adjudication"] = {
            "final_vulnerable_side": final_side,
            "label_status": label_status,
            "evidence_span_sufficient": span_sufficient,
            "final_evidence_window_ids": final_window_ids,
            "reviewer": reviewer,
            "reviewed_at": reviewed_at,
            "rationale": rationale,
        }
        updated += 1

    return {
        "status": "ok" if not errors else "failed",
        "rows": len(queue_rows),
        "adjudication_rows": len(adjudication_rows),
        "updated": updated,
        "skipped_blank": skipped_blank,
        "errors": errors,
        "queue_rows": list(by_audit_id.values()),
    }


def analyze_adjudications(rows: list[dict[str, Any]]) -> dict[str, Any]:
    completed = 0
    invalid = 0
    label_status_counts = Counter()
    span_sufficiency_counts = Counter()
    queue_type_counts: dict[str, Counter[str]] = {}
    reviewer_counts = Counter()

    for row in rows:
        adjudication = row.get("adjudication", {})
        final_side = adjudication.get("final_vulnerable_side")
        label_status = adjudication.get("label_status")
        span_sufficient = adjudication.get("evidence_span_sufficient")

        if final_side is None and label_status is None and span_sufficient is None:
            continue
        if (
            final_side not in VALID_FINAL_SIDES
            or label_status not in VALID_LABEL_STATUSES
            or span_sufficient not in VALID_EVIDENCE_SPAN_SUFFICIENCY
        ):
            invalid += 1
            continue

        completed += 1
        label_status_counts[label_status] += 1
        span_sufficiency_counts[span_sufficient] += 1
        queue_type = row.get("queue_type", "unknown")
        queue_type_counts.setdefault(queue_type, Counter())
        queue_type_counts[queue_type][label_status] += 1
        reviewer_counts[adjudication.get("reviewer") or "unknown"] += 1

    return {
        "rows": len(rows),
        "completed_adjudications": completed,
        "completion_rate": round(completed / len(rows), 4) if rows else 0.0,
        "invalid_adjudications": invalid,
        "label_status_counts": dict(sorted(label_status_counts.items())),
        "evidence_span_sufficiency_counts": dict(sorted(span_sufficiency_counts.items())),
        "reviewer_counts": dict(sorted(reviewer_counts.items())),
        "by_queue_type": {
            queue_type: dict(sorted(counts.items()))
            for queue_type, counts in sorted(queue_type_counts.items())
        },
    }

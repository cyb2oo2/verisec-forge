from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_csv, write_json


QUEUE_INPUT = "data/processed/secure_code_primevul_manual_evidence_insufficient_context_v1.jsonl"
CSV_OUTPUT = "data/processed/secure_code_primevul_manual_evidence_insufficient_context_ai_adjudication_v1.csv"
JSON_OUTPUT = "reports/secure_code_primevul_manual_evidence_insufficient_context_ai_adjudication_v1.json"

REVIEWER = "codex_ai_adjudication_v1"
REVIEWED_AT = "2026-05-18T00:00:00+08:00"


AI_DECISIONS: dict[str, dict[str, str]] = {
    "manual_evidence_audit::601::1::hexchat__4e061a43b3453a9856d34250c3913175c45afe9d__CVE-2016-2087": {
        "final_vulnerable_side": "unclear",
        "label_status": "insufficient_context",
        "evidence_span_sufficient": "no",
        "final_evidence_window_ids": "",
        "rationale": "Capability handling rewrite has mixed added and removed protection signals on both sides; selected windows do not isolate the vulnerable behavior.",
    },
    "manual_evidence_audit::503::1::linux__ad9f151e560b016b6ad3280b48e42fa11e1a5440__CVE-2021-46283": {
        "final_vulnerable_side": "B",
        "label_status": "confirmed_gold",
        "evidence_span_sufficient": "partial",
        "final_evidence_window_ids": "B2",
        "rationale": "Side B removes userdata handling and associated error-path structure visible in B2; evidence supports stored gold but wider function context would strengthen confidence.",
    },
    "manual_evidence_audit::211::1::rpm__bd36c5dc9fb6d90c46fbfed8c2d67516fc571ec8__CVE-2021-3521": {
        "final_vulnerable_side": "A",
        "label_status": "confirmed_gold",
        "evidence_span_sufficient": "partial",
        "final_evidence_window_ids": "A1",
        "rationale": "Side A removes the multi-packet allocation/self-signature parsing structure and replaces it with a narrower packet path; evidence supports stored gold but remains context dependent.",
    },
    "manual_evidence_audit::307::4::GIMP__22e2571c25425f225abdb11a566cc281fca6f366__CVE-2017-17786": {
        "final_vulnerable_side": "unclear",
        "label_status": "insufficient_context",
        "evidence_span_sufficient": "no",
        "final_evidence_window_ids": "",
        "rationale": "AlphaBits condition change is direction_unclear with no risk or safety support; helper semantics and image format context are required.",
    },
    "manual_evidence_audit::42::4::furnace__0eb02422d5161767e9983bdaa5c429762d3477ce__CVE-2022-1289": {
        "final_vulnerable_side": "A",
        "label_status": "confirmed_gold",
        "evidence_span_sufficient": "partial",
        "final_evidence_window_ids": "A1;B3",
        "rationale": "Side A removes or weakens visible range/invalid-value handling around pattern effect rendering; evidence supports stored gold but the large diff needs wider context.",
    },
    "manual_evidence_audit::7::5::linux__04c2a47ffb13c29778e2a14e414ad4cb5a5db4b5__CVE-2022-1055": {
        "final_vulnerable_side": "unclear",
        "label_status": "insufficient_context",
        "evidence_span_sufficient": "partial",
        "final_evidence_window_ids": "A1;A2;B1;B2",
        "rationale": "Pointer initialization appears reordered rather than clearly removed; selected windows show semantically close protection placement on both sides.",
    },
    "manual_evidence_audit::123::7::linux__d80b64ff297e40c2b6f7d7abc1b3eba70d22a068__CVE-2020-12768": {
        "final_vulnerable_side": "A",
        "label_status": "corrected_side",
        "evidence_span_sufficient": "partial",
        "final_evidence_window_ids": "A1",
        "rationale": "Side A removes save-area cleanup/error-path protection while B restores cleanup structure; selected evidence favors correcting the stored gold side.",
    },
    "manual_evidence_audit::99::7::src__79a034b4aed29e965f45a13409268290c9910043__CVE-2020-35679": {
        "final_vulnerable_side": "unclear",
        "label_status": "insufficient_context",
        "evidence_span_sufficient": "partial",
        "final_evidence_window_ids": "A1;B1",
        "rationale": "Regex return/regfree control flow differs, but selected windows do not establish whether the security issue is leak, match behavior, or cleanup ordering.",
    },
    "manual_evidence_audit::7::9::linux__b2f37aead1b82a770c48b5d583f35ec22aabb61e__CVE-2022-1195": {
        "final_vulnerable_side": "unclear",
        "label_status": "insufficient_context",
        "evidence_span_sufficient": "partial",
        "final_evidence_window_ids": "A2;B2",
        "rationale": "The same tty null assignment appears as an add/remove mirror; selected windows do not show the lifetime or use-after-free context needed for direction.",
    },
    "manual_evidence_audit::42::10::gpac__ebfa346eff05049718f7b80041093b4c5581c24e__CVE-2021-31258": {
        "final_vulnerable_side": "unclear",
        "label_status": "insufficient_context",
        "evidence_span_sufficient": "partial",
        "final_evidence_window_ids": "A3;B3",
        "rationale": "Both sides show null-check additions around opposite descriptor-copy directions; API ownership semantics are needed before assigning a vulnerable side.",
    },
    "manual_evidence_audit::7::4::mruby__3cf291f72224715942beaf8553e42ba8891ab3c6__CVE-2022-1212": {
        "final_vulnerable_side": "unclear",
        "label_status": "insufficient_context",
        "evidence_span_sufficient": "no",
        "final_evidence_window_ids": "",
        "rationale": "Selected break_new lines are effectively identical and provide no directional security evidence.",
    },
    "manual_evidence_audit::7::5::qemu__1caff0340f49c93d535c6558a5138d20d475315c__CVE-2021-3416": {
        "final_vulnerable_side": "unclear",
        "label_status": "insufficient_context",
        "evidence_span_sufficient": "no",
        "final_evidence_window_ids": "",
        "rationale": "Receive callback wrapper change has direction_unclear labels and no visible risk/safety support; wrapper semantics are required.",
    },
    "manual_evidence_audit::211::5::php-src__2bcbc95f033c31b00595ed39f79c3a99b4ed0501__CVE-2020-7060": {
        "final_vulnerable_side": "unclear",
        "label_status": "insufficient_context",
        "evidence_span_sufficient": "no",
        "final_evidence_window_ids": "",
        "rationale": "CP950 condition is refactored into a helper; selected windows do not show helper semantics or prove the vulnerable side.",
    },
    "manual_evidence_audit::503::5::FreeRDP__ce21b9d7ecd967e0bc98ed31a6b3757848aa6c9e__CVE-2020-11523": {
        "final_vulnerable_side": "unclear",
        "label_status": "insufficient_context",
        "evidence_span_sufficient": "no",
        "final_evidence_window_ids": "",
        "rationale": "Rectangle helper refactor changes representation but selected windows provide no visible security direction.",
    },
}


def build_rows(queue_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for queue_row in queue_rows:
        audit_id = str(queue_row["audit_id"])
        decision = AI_DECISIONS[audit_id]
        rows.append(
            {
                "audit_id": audit_id,
                "queue_type": queue_row.get("queue_type"),
                "priority": queue_row.get("priority"),
                "review_action": queue_row.get("review_action"),
                "gold_vulnerable_side": queue_row.get("gold_vulnerable_side"),
                "pilot_vulnerable_side": queue_row.get("pilot_vulnerable_side"),
                "evidence_quality": queue_row.get("evidence_quality"),
                "selected_window_ids": ";".join(queue_row.get("selected_window_ids", [])),
                "final_vulnerable_side": decision["final_vulnerable_side"],
                "label_status": decision["label_status"],
                "evidence_span_sufficient": decision["evidence_span_sufficient"],
                "final_evidence_window_ids": decision["final_evidence_window_ids"],
                "reviewer": REVIEWER,
                "reviewed_at": REVIEWED_AT,
                "rationale": decision["rationale"],
            }
        )
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    label_counts: dict[str, int] = {}
    sufficiency_counts: dict[str, int] = {}
    for row in rows:
        label_counts[str(row["label_status"])] = label_counts.get(str(row["label_status"]), 0) + 1
        key = str(row["evidence_span_sufficient"])
        sufficiency_counts[key] = sufficiency_counts.get(key, 0) + 1
    return {
        "status": "ok",
        "scope": "insufficient_context_ai_adjudication",
        "is_final_adjudication": False,
        "reviewer": REVIEWER,
        "rows": len(rows),
        "label_status_counts": dict(sorted(label_counts.items())),
        "evidence_span_sufficiency_counts": dict(sorted(sufficiency_counts.items())),
        "csv_output": CSV_OUTPUT,
    }


def main() -> int:
    queue_rows = read_jsonl(ROOT / QUEUE_INPUT)
    missing = sorted(set(row["audit_id"] for row in queue_rows) - set(AI_DECISIONS))
    if missing:
        print(json.dumps({"status": "failed", "missing_decisions": missing}, indent=2, ensure_ascii=False))
        return 1
    rows = build_rows(queue_rows)
    summary = summarize(rows)
    write_csv(ROOT / CSV_OUTPUT, rows)
    write_json(ROOT / JSON_OUTPUT, summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

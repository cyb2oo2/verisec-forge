"""Input-bound validation for AI provisional labels; never human gold."""
from __future__ import annotations

import hashlib
import json


def input_hash(case_id, a, b):
    return hashlib.sha256(json.dumps([case_id, a, b], ensure_ascii=False,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def validate_annotation(row, case):
    expected = {"case_id", "input_sha256", "annotation_source", "vulnerable_side",
                "context_sufficient", "confidence", "summary", "evidence",
                "trigger_conditions", "missing_context", "alternative_explanation"}
    if set(row) != expected:
        raise ValueError("unexpected or missing fields")
    if row["case_id"] != case["case_id"] or row["input_sha256"] != input_hash(
            case["case_id"], case["candidate_A"], case["candidate_B"]):
        raise ValueError("input identity/hash mismatch")
    if row["annotation_source"] != "ai":
        raise ValueError("AI labels must declare ai origin")
    for field, choices in {"vulnerable_side": {"A", "B", "both", "neither", "unclear"},
                           "context_sufficient": {"yes", "no", "unclear"},
                           "confidence": {"low", "medium", "high"}}.items():
        if row[field] not in choices:
            raise ValueError(f"invalid {field}")
    for field in ("summary", "alternative_explanation"):
        if not isinstance(row[field], str) or not row[field].strip():
            raise ValueError(f"missing {field}")
    for field in ("trigger_conditions", "missing_context"):
        if not isinstance(row[field], list) or any(not isinstance(x, str) or not x.strip() for x in row[field]):
            raise ValueError(f"invalid {field}")
    if row["context_sufficient"] != "yes" and not row["missing_context"]:
        raise ValueError("insufficient context requires explanation")
    if not isinstance(row["evidence"], list):
        raise ValueError("invalid evidence")
    sides = set()
    for evidence in row["evidence"]:
        if not isinstance(evidence, dict) or set(evidence) != {"side", "start_line", "end_line", "reason"}:
            raise ValueError("invalid evidence fields")
        side = evidence["side"]
        if side not in {"A", "B"}:
            raise ValueError("invalid evidence side")
        start, end = evidence["start_line"], evidence["end_line"]
        if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(case[f"candidate_{side}"].splitlines()):
            raise ValueError("evidence line out of bounds")
        if not isinstance(evidence["reason"], str) or not evidence["reason"].strip():
            raise ValueError("missing evidence reason")
        sides.add(side)
    required = {"A", "B"} if row["vulnerable_side"] == "both" else ({row["vulnerable_side"]} & {"A", "B"})
    if not required <= sides:
        raise ValueError("missing vulnerable-side evidence")
    return {"case_id": row["case_id"], "label_status": "ai_provisional",
            "eligible_for_provisional_ab": row["vulnerable_side"] in {"A", "B"}
            and row["context_sufficient"] == "yes" and row["confidence"] in {"medium", "high"}}

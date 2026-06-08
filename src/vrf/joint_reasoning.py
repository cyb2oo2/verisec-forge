from __future__ import annotations

import hashlib
from typing import Any


def evidence_candidates(evidence_row: dict[str, Any] | None, *, limit: int = 5) -> list[dict[str, Any]]:
    if not evidence_row:
        return []
    candidates = []
    for index, hunk in enumerate(evidence_row.get("top_hunks", [])[:limit], start=1):
        candidates.append(
            {
                "candidate_id": f"hunk_{index}",
                "header": hunk.get("header", ""),
                "direction_labels": hunk.get("direction_labels", []),
                "removed_preview": hunk.get("removed_preview", []),
                "added_preview": hunk.get("added_preview", []),
                "pseudo_relevance": 1 if index == 1 and evidence_row.get("support_label") == "supported" else 0,
            }
        )
    return candidates


def build_joint_pair_record(
    pair_key: str,
    rows: list[dict[str, Any]],
    evidence_by_id: dict[str, dict[str, Any]],
    *,
    evidence_limit: int = 5,
) -> dict[str, Any]:
    if len(rows) != 2:
        raise ValueError("joint pair records require exactly two sides")
    ordered = sorted(rows, key=lambda row: str(row["id"]))
    if int(hashlib.sha256(pair_key.encode("utf-8")).hexdigest()[:8], 16) % 2:
        ordered.reverse()
    side_a, side_b = ordered
    side_choice = "A" if bool(side_a.get("has_vulnerability")) else "B"
    support_labels = [
        evidence_by_id.get(str(side_a["id"]), {}).get("support_label"),
        evidence_by_id.get(str(side_b["id"]), {}).get("support_label"),
    ]
    context_sufficient = None
    abstain_target_source = "unlabeled"
    if any(label in {"unsupported", "insufficient_context"} for label in support_labels):
        context_sufficient = False
        abstain_target_source = "pseudo_support_label"
    elif all(label == "supported" for label in support_labels):
        context_sufficient = True
        abstain_target_source = "pseudo_support_label"

    return {
        "pair_key": pair_key,
        "task": "joint_secure_patch_reasoning",
        "side_choice_target": side_choice,
        "confidence_target": 1.0 if context_sufficient is True else None,
        "insufficient_context_target": None if context_sufficient is None else not context_sufficient,
        "target_source": {
            "side_choice": "benchmark_pair_label",
            "evidence": "pseudo_hunk_localization",
            "confidence": abstain_target_source,
            "insufficient_context": abstain_target_source,
        },
        "side_a": {
            "id": side_a["id"],
            "code": side_a.get("code", ""),
            "diff": side_a.get("pair_text", ""),
            "evidence_candidates": evidence_candidates(evidence_by_id.get(str(side_a["id"])), limit=evidence_limit),
        },
        "side_b": {
            "id": side_b["id"],
            "code": side_b.get("code", ""),
            "diff": side_b.get("pair_text", ""),
            "evidence_candidates": evidence_candidates(evidence_by_id.get(str(side_b["id"])), limit=evidence_limit),
        },
        "loss_mask": {
            "side_choice": True,
            "evidence_ranking": True,
            "confidence": context_sufficient is not None,
            "insufficient_context": context_sufficient is not None,
        },
    }


def summarize_joint_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    side_counts: dict[str, int] = {}
    context_counts: dict[str, int] = {}
    evidence_candidate_count = 0
    for record in records:
        side = str(record.get("side_choice_target"))
        side_counts[side] = side_counts.get(side, 0) + 1
        context = str(record.get("insufficient_context_target"))
        context_counts[context] = context_counts.get(context, 0) + 1
        evidence_candidate_count += len(record["side_a"]["evidence_candidates"]) + len(record["side_b"]["evidence_candidates"])
    return {
        "records": len(records),
        "side_choice_counts": dict(sorted(side_counts.items())),
        "insufficient_context_target_counts": dict(sorted(context_counts.items())),
        "avg_evidence_candidates_per_pair": round(evidence_candidate_count / len(records), 4) if records else 0.0,
    }

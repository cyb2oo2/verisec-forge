from __future__ import annotations

import hashlib
import re
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


def extract_unified_diff(pair_text: str) -> str:
    marker = "Unified diff:"
    body = pair_text.split(marker, 1)[1] if marker in pair_text else pair_text
    body = body.strip()
    body = re.sub(r"^--- paired_counterpart\s*\+\+\+ candidate", "--- Side A\n+++ Side B", body, count=1)
    return body


def build_side_choice_text(candidate_row: dict[str, Any]) -> str:
    diff = extract_unified_diff(str(candidate_row.get("pair_text") or ""))
    return (
        "Task: compare two versions of the same code change.\n"
        "The unified diff transforms Side A into Side B.\n"
        "Predict which side contains the security vulnerability.\n\n"
        f"{diff}"
    )


def reverse_unified_diff(diff: str) -> str:
    reversed_lines = []
    hunk_pattern = re.compile(r"^@@ -([^ ]+) \+([^ ]+) @@(.*)$")
    for line in diff.splitlines():
        match = hunk_pattern.match(line)
        if match:
            reversed_lines.append(f"@@ -{match.group(2)} +{match.group(1)} @@{match.group(3)}")
        elif line.startswith("+") and not line.startswith("+++"):
            reversed_lines.append("-" + line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            reversed_lines.append("+" + line[1:])
        else:
            reversed_lines.append(line)
    return "\n".join(reversed_lines)


def reverse_side_choice_text(text: str) -> str:
    prefix, diff = text.split("\n\n", 1)
    return f"{prefix}\n\n{reverse_unified_diff(diff)}"


def build_synthetic_side_choice_examples(row: dict[str, Any]) -> list[dict[str, Any]]:
    forward_text = build_side_choice_text(row)
    forward_label = int(bool(row.get("has_vulnerability")))
    source_pair_key = str(row.get("pair_key") or row["id"])
    instance_id = row.get("_synthetic_instance", row["id"])
    synthetic_key = f"{source_pair_key}::source::{instance_id}"
    return [
        {
            "id": f"{synthetic_key}::forward",
            "pair_key": synthetic_key,
            "source_pair_key": source_pair_key,
            "text": forward_text,
            "label": forward_label,
            "vulnerable_side": "B" if forward_label else "A",
            "orientation": "observed",
        },
        {
            "id": f"{synthetic_key}::reverse",
            "pair_key": synthetic_key,
            "source_pair_key": source_pair_key,
            "text": reverse_side_choice_text(forward_text),
            "label": 1 - forward_label,
            "vulnerable_side": "A" if forward_label else "B",
            "orientation": "synthetic_reverse",
        },
    ]


def build_side_choice_examples(
    pair_key: str,
    rows: list[dict[str, Any]],
    *,
    include_reverse: bool = True,
) -> list[dict[str, Any]]:
    if len(rows) != 2:
        raise ValueError("side-choice examples require exactly two sides")
    by_id = {str(row["id"]): row for row in rows}
    examples: list[dict[str, Any]] = []
    for candidate in sorted(rows, key=lambda row: str(row["id"])):
        counterpart_id = str(candidate.get("pair_counterpart_id") or "")
        counterpart = next(
            (
                row
                for row_id, row in by_id.items()
                if row_id == counterpart_id or row_id.split("::", 1)[0] == counterpart_id
            ),
            None,
        )
        if counterpart is None:
            counterpart = next(row for row in rows if row is not candidate)
        label = 1 if bool(candidate.get("has_vulnerability")) else 0
        examples.append(
            {
                "id": f"{pair_key}::{'b_vulnerable' if label else 'a_vulnerable'}",
                "pair_key": pair_key,
                "text": build_side_choice_text(candidate),
                "label": label,
                "vulnerable_side": "B" if label else "A",
                "side_a_id": counterpart["id"],
                "side_b_id": candidate["id"],
                "orientation": "counterpart_to_candidate",
            }
        )
        if not include_reverse:
            break
    return examples


def summarize_side_choice_examples(examples: list[dict[str, Any]]) -> dict[str, Any]:
    pair_keys = {str(row["pair_key"]) for row in examples}
    label_counts = {
        str(label): sum(int(row["label"]) == label for row in examples)
        for label in (0, 1)
    }
    return {
        "examples": len(examples),
        "unique_pairs": len(pair_keys),
        "label_counts": label_counts,
        "examples_per_pair": round(len(examples) / len(pair_keys), 4) if pair_keys else 0.0,
    }

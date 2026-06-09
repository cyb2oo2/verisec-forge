from __future__ import annotations

import math
import random
from collections import Counter
from typing import Any


ANNOTATION_FIELDS = [
    "case_id",
    "annotator_id",
    "vulnerable_side",
    "root_cause",
    "minimal_evidence_lines",
    "context_sufficient",
    "confidence",
    "notes",
    "reviewed_at",
]


def select_high_value_pairs(
    pairs: list[dict[str, Any]],
    *,
    sample_size: int = 150,
    seed: int = 42,
) -> list[dict[str, Any]]:
    if sample_size <= 0:
        return []

    rng = random.Random(seed)
    strata: dict[str, list[dict[str, Any]]] = {
        "model_error": [],
        "low_margin": [],
        "high_confidence": [],
        "large_patch": [],
        "control": [],
    }
    for pair in pairs:
        if pair.get("model_pair_correct") is False:
            stratum = "model_error"
        elif float(pair.get("probability_gap") or 0.0) <= 0.15:
            stratum = "low_margin"
        elif float(pair.get("probability_gap") or 0.0) >= 0.7:
            stratum = "high_confidence"
        elif int(pair.get("changed_lines") or 0) >= 26:
            stratum = "large_patch"
        else:
            stratum = "control"
        enriched = dict(pair)
        enriched["selection_stratum"] = stratum
        strata[stratum].append(enriched)

    for rows in strata.values():
        rng.shuffle(rows)

    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    target_per_stratum = max(1, sample_size // len(strata))
    for name in strata:
        for row in strata[name][:target_per_stratum]:
            pair_key = str(row["pair_key"])
            if pair_key in seen:
                continue
            selected.append(row)
            seen.add(pair_key)

    remaining = [row for rows in strata.values() for row in rows if str(row["pair_key"]) not in seen]
    rng.shuffle(remaining)
    for row in remaining:
        if len(selected) >= sample_size:
            break
        selected.append(row)
        seen.add(str(row["pair_key"]))
    return selected[:sample_size]


def build_blinded_packet(
    selected_pairs: list[dict[str, Any]],
    *,
    annotator_id: str,
    seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    rng = random.Random(seed)
    packet_rows: list[dict[str, Any]] = []
    answer_rows: list[dict[str, Any]] = []
    mapping_rows: list[dict[str, Any]] = []

    ordered = list(selected_pairs)
    rng.shuffle(ordered)
    for index, pair in enumerate(ordered, start=1):
        canonical_rows = list(pair["rows"])
        rng.shuffle(canonical_rows)
        side_a, side_b = canonical_rows
        case_id = f"pair-{index:03d}"
        packet_rows.append(
            {
                "case_id": case_id,
                "side_a": {"code": side_a.get("code", ""), "diff": side_a.get("pair_text", "")},
                "side_b": {"code": side_b.get("code", ""), "diff": side_b.get("pair_text", "")},
                "instructions": {
                    "vulnerable_side": "A|B|neither|unclear",
                    "minimal_evidence_lines": "Use side-prefixed line references such as A:12-15;B:8.",
                    "context_sufficient": "yes|no|unclear",
                },
            }
        )
        answer_rows.append(
            {
                "case_id": case_id,
                "annotator_id": annotator_id,
                "vulnerable_side": "",
                "root_cause": "",
                "minimal_evidence_lines": "",
                "context_sufficient": "",
                "confidence": "",
                "notes": "",
                "reviewed_at": "",
            }
        )
        mapping_rows.append(
            {
                "case_id": case_id,
                "annotator_id": annotator_id,
                "pair_key": pair["pair_key"],
                "side_a_id": side_a["id"],
                "side_b_id": side_b["id"],
                "gold_vulnerable_id": pair.get("gold_vulnerable_id"),
                "selection_stratum": pair.get("selection_stratum"),
            }
        )
    return packet_rows, answer_rows, mapping_rows


def _cohen_kappa(labels_a: list[str], labels_b: list[str]) -> float | None:
    if not labels_a or len(labels_a) != len(labels_b):
        return None
    observed = sum(a == b for a, b in zip(labels_a, labels_b)) / len(labels_a)
    counts_a = Counter(labels_a)
    counts_b = Counter(labels_b)
    labels = set(counts_a) | set(counts_b)
    expected = sum((counts_a[label] / len(labels_a)) * (counts_b[label] / len(labels_b)) for label in labels)
    if math.isclose(expected, 1.0):
        return 1.0 if math.isclose(observed, 1.0) else 0.0
    return (observed - expected) / (1.0 - expected)


def analyze_independent_annotations(
    annotations_a: list[dict[str, Any]],
    annotations_b: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
) -> dict[str, Any]:
    mapping_by_case = {(row["annotator_id"], row["case_id"]): row for row in mappings}

    def canonical_side(row: dict[str, Any]) -> str:
        choice = str(row.get("vulnerable_side") or "").strip()
        mapping = mapping_by_case.get((row.get("annotator_id"), row.get("case_id")))
        if not mapping or choice not in {"A", "B"}:
            return choice or "missing"
        selected_id = str(mapping["side_a_id"] if choice == "A" else mapping["side_b_id"])
        canonical_ids = sorted([str(mapping["side_a_id"]), str(mapping["side_b_id"])])
        return "canonical_0" if selected_id == canonical_ids[0] else "canonical_1"

    by_pair_a: dict[str, dict[str, Any]] = {}
    by_pair_b: dict[str, dict[str, Any]] = {}
    for row in annotations_a:
        mapping = mapping_by_case.get((row.get("annotator_id"), row.get("case_id")))
        if mapping:
            by_pair_a[str(mapping["pair_key"])] = row
    for row in annotations_b:
        mapping = mapping_by_case.get((row.get("annotator_id"), row.get("case_id")))
        if mapping:
            by_pair_b[str(mapping["pair_key"])] = row

    common = sorted(set(by_pair_a) & set(by_pair_b))
    side_a = [canonical_side(by_pair_a[key]) for key in common]
    side_b = [canonical_side(by_pair_b[key]) for key in common]
    context_a = [str(by_pair_a[key].get("context_sufficient") or "missing") for key in common]
    context_b = [str(by_pair_b[key].get("context_sufficient") or "missing") for key in common]
    side_agreement = sum(a == b for a, b in zip(side_a, side_b))
    context_agreement = sum(a == b for a, b in zip(context_a, context_b))
    disagreements = [
        {
            "pair_key": key,
            "annotator_a_side": side_a[index],
            "annotator_b_side": side_b[index],
            "annotator_a_context": context_a[index],
            "annotator_b_context": context_b[index],
        }
        for index, key in enumerate(common)
        if side_a[index] != side_b[index] or context_a[index] != context_b[index]
    ]
    return {
        "paired_annotations": len(common),
        "side_exact_agreement": side_agreement / len(common) if common else None,
        "side_cohen_kappa": _cohen_kappa(side_a, side_b),
        "context_exact_agreement": context_agreement / len(common) if common else None,
        "context_cohen_kappa": _cohen_kappa(context_a, context_b),
        "disagreement_count": len(disagreements),
        "disagreements": disagreements,
    }

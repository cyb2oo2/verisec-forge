from __future__ import annotations

import random
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from vrf.io_utils import read_jsonl, write_jsonl


DEFAULT_REVIEW_QUEUE_PATHS = [
    "data/processed/secure_code_primevul_side_inversion_review_queue_top5_v1.jsonl",
    "data/processed/secure_code_primevul_side_inversion_review_queue_rank6_10_v1.jsonl",
    "data/processed/secure_code_primevul_side_inversion_review_queue_fresh_seeds_top5_v1.jsonl",
    "data/processed/secure_code_primevul_side_inversion_review_queue_project_holdout_top5_v1.jsonl",
]


ANNOTATION_SCHEMA = {
    "human_vulnerable_side": "A|B|unclear",
    "evidence_side": "A|B|both|none|unclear",
    "evidence_quality": "0|1|2|3",
    "selected_window_ids": "list[str]",
    "label_issue": "none|ambiguous|wrong_label|insufficient_context",
    "notes": "free text",
    "annotator": "free text",
    "reviewed_at": "ISO-8601 timestamp",
}

VALID_HUMAN_SIDES = {"A", "B", "unclear"}
VALID_EVIDENCE_SIDES = {"A", "B", "both", "none", "unclear"}
VALID_EVIDENCE_QUALITY = {0, 1, 2, 3}
VALID_LABEL_ISSUES = {"none", "ambiguous", "wrong_label", "insufficient_context"}


def _window_id(side: str, index: int) -> str:
    return f"{side}{index + 1}"


def _format_windows(windows: list[dict[str, Any]], side: str) -> list[dict[str, Any]]:
    formatted: list[dict[str, Any]] = []
    for index, window in enumerate(windows):
        formatted.append(
            {
                "window_id": _window_id(side, index),
                "header": window.get("header", ""),
                "direction_labels": window.get("direction_labels", []),
                "risk_support": window.get("risk_support", 0),
                "safety_support": window.get("safety_support", 0),
                "removed_preview": window.get("removed_preview", []),
                "added_preview": window.get("added_preview", []),
            }
        )
    return formatted


def _stable_row_id(row: dict[str, Any], index: int) -> str:
    seed = row.get("seed", "na")
    rank = row.get("rank", index + 1)
    pair_key = str(row.get("pair_key", "unknown")).replace("|", "__")
    return f"manual_evidence_audit::{seed}::{rank}::{pair_key}"


def normalize_review_queue_row(
    row: dict[str, Any],
    *,
    source_pool: str,
    index: int,
) -> dict[str, Any]:
    side_a_probability = row.get("side_a_probability")
    side_b_probability = row.get("side_b_probability")
    model_vulnerable_side = "A"
    if side_b_probability is not None and side_a_probability is not None:
        model_vulnerable_side = "A" if side_a_probability >= side_b_probability else "B"

    return {
        "audit_id": _stable_row_id(row, index),
        "source_pool": source_pool,
        "seed": row.get("seed"),
        "rank": row.get("rank"),
        "pair_key": row.get("pair_key"),
        "project": row.get("project"),
        "cve": row.get("cve"),
        "changed_line_bucket": row.get("changed_line_bucket"),
        "model_vulnerable_side": model_vulnerable_side,
        "gold_vulnerable_side": row.get("label"),
        "is_true_inversion_candidate": row.get("is_true_inversion_candidate"),
        "side_model_score": row.get("side_model_score"),
        "probability_gap": row.get("probability_gap"),
        "side_a": {
            "id": row.get("side_a_id"),
            "detector_probability": side_a_probability,
            "windows": _format_windows(row.get("side_a_windows", []), "A"),
        },
        "side_b": {
            "id": row.get("side_b_id"),
            "detector_probability": side_b_probability,
            "windows": _format_windows(row.get("side_b_windows", []), "B"),
        },
        "annotation": {
            "human_vulnerable_side": None,
            "evidence_side": None,
            "evidence_quality": None,
            "selected_window_ids": [],
            "label_issue": "none",
            "notes": "",
            "annotator": "",
            "reviewed_at": "",
        },
    }


def load_review_queue_rows(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        path = Path(path)
        if not path.exists():
            continue
        source_pool = path.stem.replace("secure_code_primevul_side_inversion_review_queue_", "")
        for index, row in enumerate(read_jsonl(path)):
            rows.append(
                normalize_review_queue_row(
                    row,
                    source_pool=source_pool,
                    index=index,
                )
            )
    return rows


def select_audit_rows(
    rows: list[dict[str, Any]],
    *,
    sample_size: int,
    seed: int,
) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    by_pool: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_pool.setdefault(row["source_pool"], []).append(row)

    selected: list[dict[str, Any]] = []
    seen_pair_keys: set[str] = set()
    pool_names = sorted(by_pool)
    target_per_pool = max(1, sample_size // max(1, len(pool_names)))

    for pool_name in pool_names:
        pool_rows = sorted(
            by_pool[pool_name],
            key=lambda row: (
                row.get("rank") if row.get("rank") is not None else 10**9,
                row.get("pair_key") or "",
            ),
        )
        for row in pool_rows:
            if len([item for item in selected if item["source_pool"] == pool_name]) >= target_per_pool:
                break
            pair_key = row.get("pair_key")
            if pair_key in seen_pair_keys:
                continue
            selected.append(row)
            seen_pair_keys.add(pair_key)

    remaining = [row for row in rows if row.get("pair_key") not in seen_pair_keys]
    rng.shuffle(remaining)
    for row in remaining:
        if len(selected) >= sample_size:
            break
        selected.append(row)
        seen_pair_keys.add(row.get("pair_key"))

    return selected[:sample_size]


def build_manual_evidence_audit_set(
    *,
    input_paths: Iterable[str | Path] = DEFAULT_REVIEW_QUEUE_PATHS,
    output_path: str | Path,
    sample_size: int = 50,
    seed: int = 42,
) -> dict[str, Any]:
    rows = load_review_queue_rows(input_paths)
    selected = select_audit_rows(rows, sample_size=sample_size, seed=seed)
    write_jsonl(output_path, selected)
    return summarize_audit_rows(selected, total_candidates=len(rows), output_path=output_path)


def summarize_audit_rows(
    rows: list[dict[str, Any]],
    *,
    total_candidates: int | None = None,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    pool_counts = Counter(row["source_pool"] for row in rows)
    gold_counts = Counter(row.get("gold_vulnerable_side") for row in rows)
    true_inversion_counts = Counter(str(row.get("is_true_inversion_candidate")) for row in rows)
    return {
        "output_path": str(output_path) if output_path is not None else None,
        "rows": len(rows),
        "total_candidates": total_candidates,
        "unique_pair_keys": len({row.get("pair_key") for row in rows}),
        "pool_counts": dict(sorted(pool_counts.items())),
        "gold_vulnerable_side_counts": dict(sorted(gold_counts.items())),
        "true_inversion_candidate_counts": dict(sorted(true_inversion_counts.items())),
        "annotation_schema": ANNOTATION_SCHEMA,
    }


def analyze_manual_evidence_annotations(rows: list[dict[str, Any]]) -> dict[str, Any]:
    completed = 0
    invalid_rows: list[dict[str, Any]] = []
    human_vs_gold = Counter()
    evidence_vs_gold = Counter()
    evidence_quality = Counter()
    label_issues = Counter()

    for row in rows:
        annotation = row.get("annotation", {})
        human_side = annotation.get("human_vulnerable_side")
        evidence_side = annotation.get("evidence_side")
        quality = annotation.get("evidence_quality")
        label_issue = annotation.get("label_issue", "none")
        selected_window_ids = annotation.get("selected_window_ids", [])
        gold_side = row.get("gold_vulnerable_side")

        if human_side is None and evidence_side is None and quality is None:
            continue

        row_errors: list[str] = []
        if human_side not in VALID_HUMAN_SIDES:
            row_errors.append("human_vulnerable_side")
        if evidence_side not in VALID_EVIDENCE_SIDES:
            row_errors.append("evidence_side")
        if quality not in VALID_EVIDENCE_QUALITY:
            row_errors.append("evidence_quality")
        if label_issue not in VALID_LABEL_ISSUES:
            row_errors.append("label_issue")
        if not isinstance(selected_window_ids, list):
            row_errors.append("selected_window_ids")

        if row_errors:
            invalid_rows.append(
                {
                    "audit_id": row.get("audit_id"),
                    "errors": row_errors,
                }
            )
            continue

        completed += 1
        human_vs_gold["match" if human_side == gold_side else "mismatch"] += 1
        evidence_vs_gold["match" if evidence_side == gold_side else "mismatch"] += 1
        evidence_quality[str(quality)] += 1
        label_issues[label_issue] += 1

    return {
        "rows": len(rows),
        "completed_annotations": completed,
        "completion_rate": round(completed / len(rows), 4) if rows else 0.0,
        "invalid_annotations": len(invalid_rows),
        "invalid_rows": invalid_rows,
        "human_vs_gold": dict(sorted(human_vs_gold.items())),
        "evidence_vs_gold": dict(sorted(evidence_vs_gold.items())),
        "evidence_quality_counts": dict(sorted(evidence_quality.items())),
        "label_issue_counts": dict(sorted(label_issues.items())),
    }

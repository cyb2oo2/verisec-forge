from __future__ import annotations

import random
import re
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
ANNOTATION_CSV_FIELDS = [
    "audit_id",
    "human_vulnerable_side",
    "evidence_side",
    "evidence_quality",
    "selected_window_ids",
    "label_issue",
    "notes",
    "annotator",
    "reviewed_at",
]
ANNOTATION_TEMPLATE_FIELDS = [
    *ANNOTATION_CSV_FIELDS,
    "batch_id",
    "batch_index",
    "source_pool",
]
ANNOTATION_TEMPLATE_REFERENCE_FIELDS = [
    "project",
    "cve",
    "model_vulnerable_side",
    "gold_vulnerable_side",
]


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


def annotation_template_rows(
    rows: list[dict[str, Any]],
    *,
    batch_id: str | None = None,
    include_labels: bool = False,
) -> list[dict[str, Any]]:
    template_rows: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        template_rows.append(
            {
                "audit_id": row.get("audit_id"),
                "human_vulnerable_side": "",
                "evidence_side": "",
                "evidence_quality": "",
                "selected_window_ids": "",
                "label_issue": "none",
                "notes": "",
                "annotator": "",
                "reviewed_at": "",
                "batch_id": batch_id or "",
                "batch_index": index,
                "source_pool": row.get("source_pool"),
            }
            | (
                {
                    "project": row.get("project"),
                    "cve": row.get("cve"),
                    "model_vulnerable_side": row.get("model_vulnerable_side"),
                    "gold_vulnerable_side": row.get("gold_vulnerable_side"),
                }
                if include_labels
                else {}
            )
        )
    return template_rows


def split_annotation_batches(
    rows: list[dict[str, Any]],
    *,
    batch_size: int,
) -> list[list[dict[str, Any]]]:
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    return [rows[index : index + batch_size] for index in range(0, len(rows), batch_size)]


def parse_window_ids(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in re.split(r"[;,]", value) if part.strip()]


def _valid_window_ids(row: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for side_key in ("side_a", "side_b"):
        for window in row.get(side_key, {}).get("windows", []):
            if window.get("window_id"):
                ids.add(window["window_id"])
    return ids


def _parse_quality(value: str | int | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def apply_annotation_rows(
    audit_rows: list[dict[str, Any]],
    annotation_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    by_audit_id = {row["audit_id"]: row for row in audit_rows}
    updated = 0
    skipped_blank = 0
    errors: list[dict[str, Any]] = []

    for annotation in annotation_rows:
        audit_id = annotation.get("audit_id")
        if audit_id not in by_audit_id:
            errors.append({"audit_id": audit_id, "errors": ["unknown_audit_id"]})
            continue

        human_side = (annotation.get("human_vulnerable_side") or "").strip()
        evidence_side = (annotation.get("evidence_side") or "").strip()
        quality = _parse_quality(annotation.get("evidence_quality"))
        selected_window_ids = parse_window_ids(annotation.get("selected_window_ids"))
        label_issue = (annotation.get("label_issue") or "none").strip()
        notes = annotation.get("notes") or ""
        annotator = annotation.get("annotator") or ""
        reviewed_at = annotation.get("reviewed_at") or ""

        if not human_side and not evidence_side and quality is None and not selected_window_ids and not notes:
            skipped_blank += 1
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

        valid_window_ids = _valid_window_ids(by_audit_id[audit_id])
        invalid_window_ids = [window_id for window_id in selected_window_ids if window_id not in valid_window_ids]
        if invalid_window_ids:
            row_errors.append("selected_window_ids")

        if row_errors:
            errors.append(
                {
                    "audit_id": audit_id,
                    "errors": row_errors,
                    "invalid_window_ids": invalid_window_ids,
                }
            )
            continue

        by_audit_id[audit_id]["annotation"] = {
            "human_vulnerable_side": human_side,
            "evidence_side": evidence_side,
            "evidence_quality": quality,
            "selected_window_ids": selected_window_ids,
            "label_issue": label_issue,
            "notes": notes,
            "annotator": annotator,
            "reviewed_at": reviewed_at,
        }
        updated += 1

    return {
        "status": "ok" if not errors else "failed",
        "rows": len(audit_rows),
        "annotation_rows": len(annotation_rows),
        "updated": updated,
        "skipped_blank": skipped_blank,
        "errors": errors,
        "audit_rows": audit_rows,
    }


def annotation_progress_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    analysis = analyze_manual_evidence_annotations(rows)
    completed_ids: set[str] = set()
    blank_ids: set[str] = set()
    for row in rows:
        annotation = row.get("annotation", {})
        human_side = annotation.get("human_vulnerable_side")
        evidence_side = annotation.get("evidence_side")
        quality = annotation.get("evidence_quality")
        if human_side is None and evidence_side is None and quality is None:
            blank_ids.add(row.get("audit_id"))
        elif row.get("audit_id") not in {item["audit_id"] for item in analysis["invalid_rows"]}:
            completed_ids.add(row.get("audit_id"))

    by_pool: dict[str, Counter[str]] = {}
    for row in rows:
        pool = row.get("source_pool", "unknown")
        by_pool.setdefault(pool, Counter())
        audit_id = row.get("audit_id")
        if audit_id in completed_ids:
            by_pool[pool]["completed"] += 1
        elif audit_id in blank_ids:
            by_pool[pool]["blank"] += 1
        else:
            by_pool[pool]["invalid"] += 1

    return {
        **analysis,
        "blank_annotations": len(blank_ids),
        "by_source_pool": {
            pool: dict(sorted(counts.items()))
            for pool, counts in sorted(by_pool.items())
        },
        "remaining_audit_ids": [
            row.get("audit_id")
            for row in rows
            if row.get("audit_id") not in completed_ids
        ],
    }


def _render_preview(lines: list[str], prefix: str) -> list[str]:
    if not lines:
        return [f"{prefix} <empty>"]
    return [f"{prefix} {line}" for line in lines]


def _render_side(side_label: str, side: dict[str, Any], *, include_labels: bool) -> list[str]:
    lines = [
        f"### Side {side_label}",
        "",
        f"- ID: `{side.get('id')}`",
    ]
    if include_labels:
        lines.append(f"- Detector probability: `{side.get('detector_probability')}`")
    lines.append("")
    for window in side.get("windows", []):
        labels = ",".join(window.get("direction_labels", [])) or "none"
        lines.extend(
            [
                f"#### Window `{window.get('window_id')}`",
                "",
                f"- Header: `{window.get('header')}`",
                f"- Direction labels: `{labels}`",
                f"- Risk support: `{window.get('risk_support')}`",
                f"- Safety support: `{window.get('safety_support')}`",
                "",
                "Removed preview:",
                "",
                "```diff",
                *_render_preview(window.get("removed_preview", []), "-"),
                "```",
                "",
                "Added preview:",
                "",
                "```diff",
                *_render_preview(window.get("added_preview", []), "+"),
                "```",
                "",
            ]
        )
    return lines


def render_manual_evidence_review_packet(
    rows: list[dict[str, Any]],
    *,
    include_labels: bool = False,
) -> str:
    lines = [
        "# PrimeVul Manual Evidence Review Packet",
        "",
        "Use this packet to annotate the JSONL file without reading raw one-line JSON. Copy the final decisions back into the `annotation` object for each `audit_id`.",
        "",
        "Annotation fields:",
        "",
        "- `human_vulnerable_side`: `A`, `B`, or `unclear`.",
        "- `evidence_side`: `A`, `B`, `both`, `none`, or `unclear`.",
        "- `evidence_quality`: `0` no evidence, `1` weak, `2` plausible, `3` strong direct evidence.",
        "- `selected_window_ids`: window IDs such as `A1`, `A2`, `B1`.",
        "- `label_issue`: `none`, `ambiguous`, `wrong_label`, or `insufficient_context`.",
        "",
    ]

    for index, row in enumerate(rows, start=1):
        item_lines = [
            f"## Item {index}: `{row.get('audit_id')}`",
            "",
            f"- Pair key: `{row.get('pair_key')}`",
            f"- Source pool: `{row.get('source_pool')}`",
            f"- Changed-line bucket: `{row.get('changed_line_bucket')}`",
        ]
        if include_labels:
            item_lines.extend(
                [
                    f"- Project/CVE: `{row.get('project')}` / `{row.get('cve')}`",
                    f"- Model vulnerable side: `{row.get('model_vulnerable_side')}`",
                    f"- Gold vulnerable side: `{row.get('gold_vulnerable_side')}`",
                    f"- True inversion candidate: `{row.get('is_true_inversion_candidate')}`",
                    f"- Side model score: `{row.get('side_model_score')}`",
                    f"- Probability gap: `{row.get('probability_gap')}`",
                ]
            )
        item_lines.extend(
            [
                "",
                "### Annotation Block",
                "",
                "```yaml",
                "human_vulnerable_side: ",
                "evidence_side: ",
                "evidence_quality: ",
                "selected_window_ids: []",
                "label_issue: none",
                "notes: ",
                "```",
                "",
            ]
        )
        lines.extend(item_lines)
        lines.extend(_render_side("A", row.get("side_a", {}), include_labels=include_labels))
        lines.extend(_render_side("B", row.get("side_b", {}), include_labels=include_labels))
        lines.append("---")
        lines.append("")

    return "\n".join(lines)

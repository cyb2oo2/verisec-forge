from __future__ import annotations

import argparse
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from vrf.io_utils import read_jsonl, write_json, write_jsonl


WINDOW_FIELDS = [
    "hunk_rank",
    "candidate_strategy",
    "window_size",
    "header",
    "changed_lines",
    "removed_preview",
    "added_preview",
    "keywords",
    "direction_labels",
    "pseudo_label",
    "risk_support",
    "safety_support",
    "protection_delta",
    "risk_delta",
    "safer_delta",
]


def hunk_groups(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row["source_id"])].append(row)
    return grouped


def group_prediction_rows(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("pair_key") or row["id"])].append(row)
    return grouped


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def compact_window(row: dict[str, Any]) -> dict[str, Any]:
    compact = {field: row.get(field) for field in WINDOW_FIELDS if field in row}
    compact["risk_minus_safety"] = safe_float(row.get("risk_support")) - safe_float(row.get("safety_support"))
    return compact


def top_windows(rows: list[dict[str, Any]], *, top_windows_count: int) -> list[dict[str, Any]]:
    ordered = sorted(
        rows,
        key=lambda row: (
            int(row.get("hunk_rank") or 999999),
            -safe_float(row.get("risk_support")),
            -safe_float(row.get("safety_support")),
        ),
    )
    return [compact_window(row) for row in ordered[:top_windows_count]]


def pair_key_metadata(pair_key: str) -> dict[str, str | None]:
    parts = pair_key.split("|")
    return {
        "project": parts[0] if len(parts) >= 1 and parts[0] else None,
        "commit": parts[1] if len(parts) >= 2 and parts[1] else None,
        "cve": parts[2] if len(parts) >= 3 and parts[2] else None,
    }


def render_side(name: str, row: dict[str, Any], windows: list[dict[str, Any]]) -> str:
    lines = [
        f"Side {name}: id={row.get('id')} detector_probability={safe_float(row.get('vuln_probability')):.4f}",
        f"Changed-line bucket: {row.get('changed_line_bucket', 'unknown')}",
        f"Project: {row.get('project', 'unknown')} | CWE: {row.get('vulnerability_type', 'unknown')}",
    ]
    if not windows:
        lines.append("No hunk/window candidates are available for this side.")
        return "\n".join(lines)
    for index, window in enumerate(windows, start=1):
        labels = ",".join(str(label) for label in window.get("direction_labels", [])) or "none"
        lines.extend(
            [
                f"Window {index}: {window.get('header', '@@')}",
                f"Signals: risk={window.get('risk_support', 0)} safety={window.get('safety_support', 0)} labels={labels}",
                "Removed preview:",
            ]
        )
        removed = window.get("removed_preview") or []
        lines.extend([f"- {line}" for line in removed[:4]] or ["- <empty>"])
        lines.append("Added preview:")
        added = window.get("added_preview") or []
        lines.extend([f"+ {line}" for line in added[:4]] or ["+ <empty>"])
    return "\n".join(lines)


def render_prompt(side_a: dict[str, Any], side_b: dict[str, Any]) -> str:
    return "\n\n".join(
        [
            "Task: Compare two sides of a paired security patch/diff. Decide which side is the vulnerable version.",
            "Return exactly one label: A or B. Use the changed-window evidence, not project names or CVE metadata.",
            render_side("A", side_a["row"], side_a["windows"]),
            render_side("B", side_b["row"], side_b["windows"]),
        ]
    )


def mixed_binary_group(group: list[dict[str, Any]]) -> bool:
    golds = {int(row.get("gold", -1)) for row in group}
    return golds == {0, 1}


def build_pair_row(
    pair_key: str,
    group: list[dict[str, Any]],
    hunks_by_source: dict[str, list[dict[str, Any]]],
    *,
    top_windows_count: int,
    confident_gap: float,
) -> dict[str, Any]:
    ordered = sorted(group, key=lambda row: safe_float(row.get("vuln_probability")), reverse=True)
    side_a_row = ordered[0]
    side_b_row = ordered[-1]
    side_a = {
        "row": side_a_row,
        "windows": top_windows(hunks_by_source.get(str(side_a_row["id"]), []), top_windows_count=top_windows_count),
    }
    side_b = {
        "row": side_b_row,
        "windows": top_windows(hunks_by_source.get(str(side_b_row["id"]), []), top_windows_count=top_windows_count),
    }
    side_a_gold = int(side_a_row["gold"])
    side_b_gold = int(side_b_row["gold"])
    label = "A" if side_a_gold == 1 else "B"
    gap = safe_float(side_a_row.get("vuln_probability")) - safe_float(side_b_row.get("vuln_probability"))
    metadata = pair_key_metadata(pair_key)
    prompt = render_prompt(side_a, side_b)
    return {
        "pair_key": pair_key,
        "side_a_id": side_a_row["id"],
        "side_b_id": side_b_row["id"],
        "side_a_gold": side_a_gold,
        "side_b_gold": side_b_gold,
        "side_a_probability": safe_float(side_a_row.get("vuln_probability")),
        "side_b_probability": safe_float(side_b_row.get("vuln_probability")),
        "probability_gap": round(gap, 6),
        "label": label,
        "label_index": 0 if label == "A" else 1,
        "pair_coupled_orientation_correct": label == "A",
        "is_high_gap_orientation_inversion": label == "B" and gap >= confident_gap,
        "changed_line_bucket": side_a_row.get("changed_line_bucket") or side_b_row.get("changed_line_bucket"),
        "project": side_a_row.get("project") or side_b_row.get("project") or metadata["project"],
        "commit": side_a_row.get("commit") or side_b_row.get("commit") or metadata["commit"],
        "cve": side_a_row.get("cve") or side_b_row.get("cve") or metadata["cve"],
        "vulnerability_type": side_a_row.get("vulnerability_type") or side_b_row.get("vulnerability_type"),
        "side_a_windows": side_a["windows"],
        "side_b_windows": side_b["windows"],
        "side_a_window_count": len(side_a["windows"]),
        "side_b_window_count": len(side_b["windows"]),
        "contrastive_prompt": prompt,
        "prompt_chars": len(prompt),
    }


def build_dataset(
    prediction_rows: list[dict[str, Any]],
    hunk_rows: list[dict[str, Any]],
    *,
    top_windows_count: int,
    confident_gap: float,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    hunks_by_source = hunk_groups(hunk_rows)
    pair_groups = group_prediction_rows(prediction_rows)
    rows = []
    skipped_non_mixed = 0
    skipped_small = 0
    for pair_key, group in sorted(pair_groups.items()):
        if len(group) < 2:
            skipped_small += 1
            continue
        if not mixed_binary_group(group):
            skipped_non_mixed += 1
            continue
        rows.append(
            build_pair_row(
                pair_key,
                group,
                hunks_by_source,
                top_windows_count=top_windows_count,
                confident_gap=confident_gap,
            )
        )
    summary = summarize(rows, pair_groups_seen=len(pair_groups), skipped_small=skipped_small, skipped_non_mixed=skipped_non_mixed)
    summary["config"] = {"top_windows": top_windows_count, "confident_gap": confident_gap}
    return rows, summary


def mean(values: list[float]) -> float:
    return round(statistics.mean(values), 4) if values else 0.0


def top_counts(values: list[Any], *, limit: int = 10) -> list[list[Any]]:
    return [[key, count] for key, count in Counter(value for value in values if value not in {None, ""}).most_common(limit)]


def summarize(rows: list[dict[str, Any]], *, pair_groups_seen: int, skipped_small: int, skipped_non_mixed: int) -> dict[str, Any]:
    total = len(rows)
    label_a = sum(1 for row in rows if row["label"] == "A")
    confident = sum(1 for row in rows if row["is_high_gap_orientation_inversion"])
    missing_window_sides = sum(
        int(row["side_a_window_count"] == 0) + int(row["side_b_window_count"] == 0)
        for row in rows
    )
    return {
        "rows": total,
        "pair_groups_seen": pair_groups_seen,
        "skipped_small_groups": skipped_small,
        "skipped_non_mixed_groups": skipped_non_mixed,
        "label_a_rows": label_a,
        "label_b_rows": total - label_a,
        "pair_coupled_orientation_accuracy": round(label_a / total, 4) if total else 0.0,
        "high_gap_orientation_inversion_pairs": confident,
        "high_gap_orientation_inversion_rate": round(confident / total, 4) if total else 0.0,
        "avg_probability_gap": mean([float(row["probability_gap"]) for row in rows]),
        "avg_prompt_chars": mean([float(row["prompt_chars"]) for row in rows]),
        "missing_window_sides": missing_window_sides,
        "top_changed_line_buckets": top_counts([row.get("changed_line_bucket") for row in rows]),
        "top_projects": top_counts([row.get("project") for row in rows]),
        "top_vulnerability_types": top_counts([row.get("vulnerability_type") for row in rows]),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# PrimeVul Paired-Window Contrastive Dataset",
        "",
        "This artifact converts pair-coupled predictions plus hunk/window candidates into model-ready pair-level contrastive examples. It is a dataset-building step for the next side-correction model, not a performance claim.",
        "",
        "## Summary",
        "",
        f"- Pair groups seen: `{summary['pair_groups_seen']}`",
        f"- Contrastive rows: `{summary['rows']}`",
        f"- Label A / B rows: `{summary['label_a_rows']}` / `{summary['label_b_rows']}`",
        f"- Current high-probability-side orientation accuracy: `{summary['pair_coupled_orientation_accuracy']}`",
        f"- High-gap orientation inversion pairs (`gap >= {summary['config']['confident_gap']}`): `{summary['high_gap_orientation_inversion_pairs']}`",
        f"- Average probability gap: `{summary['avg_probability_gap']}`",
        f"- Average prompt chars: `{summary['avg_prompt_chars']}`",
        f"- Missing window sides: `{summary['missing_window_sides']}`",
        "",
        "## Why This Exists",
        "",
        "The previous shallow pair-side gates were flat across multiple pair-key splits. This dataset moves the next step from manual aggregate features to an explicit paired-window comparison task: given the high-probability side and low-probability side, learn whether the current orientation should be trusted or inverted.",
        "",
        "## Important Boundary",
        "",
        "Rows are derived from pseudo-label hunk/window candidates and current pair-coupled predictions. They should be used for calibration, hard-negative mining, or a held-out pair-key split experiment, not reported as independent human evidence-span supervision.",
        "",
        "## Top Buckets",
        "",
        "| changed_line_bucket | pairs |",
        "| --- | ---: |",
    ]
    for bucket, count in summary["top_changed_line_buckets"]:
        lines.append(f"| {bucket} | {count} |")
    lines.extend(["", "## Top Vulnerability Types", "", "| type | pairs |", "| --- | ---: |"])
    for cwe, count in summary["top_vulnerability_types"]:
        lines.append(f"| {cwe} | {count} |")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build PrimeVul paired-window contrastive examples for side-correction training.")
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--hunk-candidates", required=True)
    parser.add_argument("--top-windows", type=int, default=3)
    parser.add_argument("--confident-gap", type=float, default=0.5)
    parser.add_argument("--jsonl-output", required=True)
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--summary-md", required=True)
    args = parser.parse_args()

    rows, summary = build_dataset(
        read_jsonl(args.predictions),
        read_jsonl(args.hunk_candidates),
        top_windows_count=args.top_windows,
        confident_gap=args.confident_gap,
    )
    payload = {"summary": summary}
    write_jsonl(args.jsonl_output, rows)
    write_json(args.summary_json, payload)
    md_path = Path(args.summary_md)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(payload), encoding="utf-8")


if __name__ == "__main__":
    main()

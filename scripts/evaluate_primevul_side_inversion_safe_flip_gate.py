from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from scripts.evaluate_primevul_side_inversion_verifier_baselines import evidence_score
from vrf.io_utils import read_jsonl, write_json, write_jsonl


def gold_accept(row: dict[str, Any]) -> bool:
    return bool(row.get("accept_flip"))


def should_accept(row: dict[str, Any], pair_counts: collections.Counter[str], *, repeat_threshold: int, evidence_threshold: float) -> bool:
    pair_key = str(row.get("pair_key", row.get("id", "")))
    return pair_counts[pair_key] >= repeat_threshold or evidence_score(row) >= evidence_threshold


def annotate_rows(rows: list[dict[str, Any]], *, repeat_threshold: int, evidence_threshold: float) -> list[dict[str, Any]]:
    pair_counts: collections.Counter[str] = collections.Counter(str(row.get("pair_key", row.get("id", ""))) for row in rows)
    annotated = []
    for row in rows:
        pair_key = str(row.get("pair_key", row.get("id", "")))
        score = evidence_score(row)
        accept = should_accept(row, pair_counts, repeat_threshold=repeat_threshold, evidence_threshold=evidence_threshold)
        annotated.append(
            {
                "id": row.get("id"),
                "pair_key": pair_key,
                "seed": row.get("seed"),
                "rank": row.get("rank"),
                "accepted_by_gate": accept,
                "is_true_flip": gold_accept(row),
                "would_repair_side_error": accept and gold_accept(row),
                "would_introduce_side_error": accept and not gold_accept(row),
                "evidence_score": score,
                "pair_repeat_count": pair_counts[pair_key],
                "side_model_score": row.get("side_model_score"),
                "project": row.get("project"),
                "cve": row.get("cve"),
                "changed_line_bucket": row.get("changed_line_bucket"),
            }
        )
    return annotated


def summarize_rows(rows: list[dict[str, Any]], annotated: list[dict[str, Any]]) -> dict[str, Any]:
    accepted = [row for row in annotated if row["accepted_by_gate"]]
    true_accepts = [row for row in accepted if row["is_true_flip"]]
    false_accepts = [row for row in accepted if not row["is_true_flip"]]
    true_flips = [row for row in annotated if row["is_true_flip"]]
    accepted_pairs = {row["pair_key"] for row in accepted}
    true_accepted_pairs = {row["pair_key"] for row in true_accepts}
    false_accepted_pairs = {row["pair_key"] for row in false_accepts}
    true_flip_pairs = {row["pair_key"] for row in true_flips}
    return {
        "rows": len(rows),
        "unique_pair_count": len({str(row.get("pair_key", row.get("id", ""))) for row in rows}),
        "candidate_true_flip_rows": len(true_flips),
        "candidate_true_flip_pairs": len(true_flip_pairs),
        "accepted_rows": len(accepted),
        "accepted_unique_pairs": len(accepted_pairs),
        "repaired_side_error_rows": len(true_accepts),
        "repaired_side_error_pairs": len(true_accepted_pairs),
        "introduced_side_error_rows": len(false_accepts),
        "introduced_side_error_pairs": len(false_accepted_pairs),
        "missed_true_flip_rows": len(true_flips) - len(true_accepts),
        "missed_true_flip_pairs": len(true_flip_pairs - true_accepted_pairs),
        "accept_precision": round(len(true_accepts) / len(accepted), 4) if accepted else 0.0,
        "accept_recall": round(len(true_accepts) / len(true_flips), 4) if true_flips else 0.0,
        "net_row_gain_if_applied": len(true_accepts) - len(false_accepts),
        "net_pair_gain_if_applied": len(true_accepted_pairs) - len(false_accepted_pairs),
    }


def build_report(rows: list[dict[str, Any]], *, repeat_threshold: int, evidence_threshold: float) -> dict[str, Any]:
    annotated = annotate_rows(rows, repeat_threshold=repeat_threshold, evidence_threshold=evidence_threshold)
    accepted_rows = [row for row in annotated if row["accepted_by_gate"]]
    return {
        "config": {
            "repeat_threshold": repeat_threshold,
            "evidence_threshold": evidence_threshold,
            "gate": f"pair_repeat_count>={repeat_threshold} OR evidence_score>={evidence_threshold:g}",
        },
        "summary": summarize_rows(rows, annotated),
        "accepted_rows": accepted_rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# PrimeVul Side-Inversion Safe Flip Gate",
        "",
        "This report evaluates the precision-first verifier gate as a system component. It estimates what would happen if accepted review-queue candidates were used to flip pair orientation.",
        "",
        "## Gate",
        "",
        f"- Rule: `{payload['config']['gate']}`",
        "",
        "## Summary",
        "",
        f"- Candidate rows / unique pairs: `{summary['rows']}` / `{summary['unique_pair_count']}`",
        f"- Candidate true-flip rows / pairs: `{summary['candidate_true_flip_rows']}` / `{summary['candidate_true_flip_pairs']}`",
        f"- Accepted rows / unique pairs: `{summary['accepted_rows']}` / `{summary['accepted_unique_pairs']}`",
        f"- Repaired side-error rows / pairs: `{summary['repaired_side_error_rows']}` / `{summary['repaired_side_error_pairs']}`",
        f"- Introduced side-error rows / pairs: `{summary['introduced_side_error_rows']}` / `{summary['introduced_side_error_pairs']}`",
        f"- Missed true-flip rows / pairs: `{summary['missed_true_flip_rows']}` / `{summary['missed_true_flip_pairs']}`",
        f"- Accept precision / recall: `{summary['accept_precision']}` / `{summary['accept_recall']}`",
        f"- Net row / pair gain if applied: `{summary['net_row_gain_if_applied']}` / `{summary['net_pair_gain_if_applied']}`",
        "",
        "## Accepted Candidates",
        "",
        "| id | pair_repeat | evidence_score | true_flip | project | bucket |",
        "| --- | ---: | ---: | --- | --- | --- |",
    ]
    for row in payload["accepted_rows"]:
        lines.append(
            f"| {row['id']} | {row['pair_repeat_count']} | {row['evidence_score']} | "
            f"{row['is_true_flip']} | {row.get('project')} | {row.get('changed_line_bucket')} |"
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "This is still an offline gate over a gold-labeled review queue selected from current model failures. It should be used to define a safety target and candidate operating point, not as proof of a deployable automatic correction system.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a precision-first safe flip gate over side-inversion verifier rows.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--repeat-threshold", type=int, default=3)
    parser.add_argument("--evidence-threshold", type=float, default=13.0)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output")
    parser.add_argument("--accepted-jsonl-output")
    args = parser.parse_args()

    payload = build_report(read_jsonl(args.input), repeat_threshold=args.repeat_threshold, evidence_threshold=args.evidence_threshold)
    write_json(args.json_output, payload)
    if args.accepted_jsonl_output:
        write_jsonl(args.accepted_jsonl_output, payload["accepted_rows"])
    if args.md_output:
        output = Path(args.md_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()

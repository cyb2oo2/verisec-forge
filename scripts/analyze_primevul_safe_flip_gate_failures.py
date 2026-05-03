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
from vrf.io_utils import read_json, read_jsonl, write_json


def annotate_all(rows: list[dict[str, Any]], gate: dict[str, Any]) -> list[dict[str, Any]]:
    accepted_ids = {row["id"] for row in gate.get("accepted_rows", [])}
    pair_counts: collections.Counter[str] = collections.Counter(str(row.get("pair_key", row.get("id", ""))) for row in rows)
    annotated = []
    for row in rows:
        is_true = bool(row.get("accept_flip"))
        accepted = row.get("id") in accepted_ids
        pair_key = str(row.get("pair_key", row.get("id", "")))
        annotated.append(
            {
                "id": row.get("id"),
                "pair_key": pair_key,
                "seed": row.get("seed"),
                "rank": row.get("rank"),
                "project": row.get("project"),
                "cve": row.get("cve"),
                "changed_line_bucket": row.get("changed_line_bucket"),
                "side_model_score": row.get("side_model_score"),
                "evidence_score": evidence_score(row),
                "pair_repeat_count": pair_counts[pair_key],
                "accepted": accepted,
                "is_true_flip": is_true,
                "error_type": error_type(accepted=accepted, is_true=is_true),
            }
        )
    return annotated


def error_type(*, accepted: bool, is_true: bool) -> str:
    if accepted and is_true:
        return "true_accept"
    if accepted and not is_true:
        return "false_accept"
    if not accepted and is_true:
        return "missed_true_flip"
    return "true_reject"


def top_counts(rows: list[dict[str, Any]], field: str) -> list[list[Any]]:
    return [[key, value] for key, value in collections.Counter(row.get(field) for row in rows).most_common()]


def summarize(annotated: list[dict[str, Any]]) -> dict[str, Any]:
    by_error = collections.Counter(row["error_type"] for row in annotated)
    false_accepts = [row for row in annotated if row["error_type"] == "false_accept"]
    missed = [row for row in annotated if row["error_type"] == "missed_true_flip"]
    true_accepts = [row for row in annotated if row["error_type"] == "true_accept"]
    return {
        "rows": len(annotated),
        "accepted_rows": by_error["true_accept"] + by_error["false_accept"],
        "true_accepts": by_error["true_accept"],
        "false_accepts": by_error["false_accept"],
        "missed_true_flips": by_error["missed_true_flip"],
        "true_rejects": by_error["true_reject"],
        "false_accept_unique_pairs": len({row["pair_key"] for row in false_accepts}),
        "false_accept_projects": top_counts(false_accepts, "project"),
        "false_accept_buckets": top_counts(false_accepts, "changed_line_bucket"),
        "false_accept_pair_keys": top_counts(false_accepts, "pair_key"),
        "missed_true_projects": top_counts(missed, "project"),
        "true_accept_projects": top_counts(true_accepts, "project"),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# PrimeVul Safe Flip Gate Failure Analysis",
        "",
        "This report explains accepted false flips and missed true flips for a side-inversion safe flip gate.",
        "",
        "## Summary",
        "",
        f"- Rows: `{summary['rows']}`",
        f"- Accepted rows: `{summary['accepted_rows']}`",
        f"- True accepts: `{summary['true_accepts']}`",
        f"- False accepts: `{summary['false_accepts']}`",
        f"- Missed true flips: `{summary['missed_true_flips']}`",
        f"- True rejects: `{summary['true_rejects']}`",
        f"- False-accept unique pairs: `{summary['false_accept_unique_pairs']}`",
        "",
        "## False Accepts",
        "",
        "| id | pair_key | project | bucket | evidence_score | repeat | side_score |",
        "| --- | --- | --- | --- | ---: | ---: | ---: |",
    ]
    for row in payload["false_accepts"]:
        lines.append(
            f"| {row['id']} | {row['pair_key']} | {row.get('project')} | {row.get('changed_line_bucket')} | "
            f"{row['evidence_score']} | {row['pair_repeat_count']} | {row.get('side_model_score')} |"
        )
    lines.extend(
        [
            "",
            "## Missed True Flips",
            "",
            "| id | pair_key | project | bucket | evidence_score | repeat | side_score |",
            "| --- | --- | --- | --- | ---: | ---: | ---: |",
        ]
    )
    for row in payload["missed_true_flips"]:
        lines.append(
            f"| {row['id']} | {row['pair_key']} | {row.get('project')} | {row.get('changed_line_bucket')} | "
            f"{row['evidence_score']} | {row['pair_repeat_count']} | {row.get('side_model_score')} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            payload["interpretation"],
            "",
        ]
    )
    return "\n".join(lines)


def build_report(rows: list[dict[str, Any]], gate: dict[str, Any]) -> dict[str, Any]:
    annotated = annotate_all(rows, gate)
    false_accepts = [row for row in annotated if row["error_type"] == "false_accept"]
    missed = [row for row in annotated if row["error_type"] == "missed_true_flip"]
    interpretation = (
        "False accepts are dominated by repeat-consensus errors when their evidence scores are below the evidence "
        "threshold. This suggests the consensus branch is less reliable under project-heldout candidate generation "
        "and should be tightened or conditioned on positive evidence."
        if false_accepts
        else "No false accepts were observed at this operating point; remaining risk is recall loss from missed true flips."
    )
    return {
        "summary": summarize(annotated),
        "false_accepts": false_accepts,
        "missed_true_flips": missed,
        "annotated_rows": annotated,
        "interpretation": interpretation,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze safe flip gate false accepts and misses.")
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--gate-report", required=True)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--md-output", required=True)
    args = parser.parse_args()

    payload = build_report(read_jsonl(args.verifier), read_json(args.gate_report))
    write_json(args.json_output, payload)
    output = Path(args.md_output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()

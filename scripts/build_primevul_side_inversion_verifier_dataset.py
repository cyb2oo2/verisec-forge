from __future__ import annotations

import argparse
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

from vrf.io_utils import read_jsonl, write_json, write_jsonl


def render_window(window: dict[str, Any]) -> str:
    labels = ",".join(str(label) for label in window.get("direction_labels", [])) or "none"
    lines = [
        f"Header: {window.get('header', '@@')}",
        f"Signals: risk={window.get('risk_support', 0)} safety={window.get('safety_support', 0)} labels={labels}",
        "Removed preview:",
    ]
    lines.extend([f"- {line}" for line in window.get("removed_preview", [])] or ["- <empty>"])
    lines.append("Added preview:")
    lines.extend([f"+ {line}" for line in window.get("added_preview", [])] or ["+ <empty>"])
    return "\n".join(lines)


def render_side(name: str, row: dict[str, Any], windows: list[dict[str, Any]]) -> str:
    lines = [f"Side {name} windows:"]
    for index, window in enumerate(windows, start=1):
        lines.append(f"Window {index}\n{render_window(window)}")
    return "\n\n".join(lines)


def render_prompt(row: dict[str, Any]) -> str:
    return "\n\n".join(
        [
            "Task: Verify a proposed side-orientation flip for a paired security patch/diff.",
            "Current detector orientation says Side A is more likely vulnerable. A side model proposes flipping to Side B.",
            "Decide whether to accept the flip using only the paired evidence windows.",
            'Return strict JSON with keys: "accept_flip", "reason_code", "evidence_side", "confidence".',
            "Allowed reason_code values: evidence_supports_flip, evidence_rejects_flip, insufficient_evidence.",
            f"Pair key: {row['pair_key']}",
            f"Side-model score: {row['side_model_score']}",
            f"Side A detector probability: {row['side_a_probability']}",
            f"Side B detector probability: {row['side_b_probability']}",
            f"Probability gap: {row['probability_gap']}",
            render_side("A", row, row.get("side_a_windows", [])),
            render_side("B", row, row.get("side_b_windows", [])),
        ]
    )


def target_for_row(row: dict[str, Any]) -> dict[str, Any]:
    accept = bool(row.get("is_true_inversion_candidate"))
    return {
        "accept_flip": accept,
        "reason_code": "evidence_supports_flip" if accept else "evidence_rejects_flip",
        "evidence_side": "B" if accept else "A",
        "confidence": "medium",
    }


def build_rows(queue_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    dataset_rows = []
    for row in queue_rows:
        target = target_for_row(row)
        dataset_rows.append(
            {
                "id": f"{row['seed']}::{row['rank']}::{row['pair_key']}",
                "pair_key": row["pair_key"],
                "seed": row["seed"],
                "rank": row["rank"],
                "side_model_score": row["side_model_score"],
                "prompt": render_prompt(row),
                "target": target,
                "target_json": json.dumps(target, sort_keys=True),
                "accept_flip": target["accept_flip"],
                "gold_invert": int(row["gold_invert"]),
                "project": row.get("project"),
                "cve": row.get("cve"),
                "changed_line_bucket": row.get("changed_line_bucket"),
            }
        )
    return dataset_rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    accepts = sum(1 for row in rows if row["accept_flip"])
    unique_pairs = sorted({row["pair_key"] for row in rows})
    prompt_lengths = [len(row["prompt"]) for row in rows]
    return {
        "rows": len(rows),
        "unique_pair_count": len(unique_pairs),
        "accept_flip_rows": accepts,
        "reject_flip_rows": len(rows) - accepts,
        "accept_rate": round(accepts / len(rows), 4) if rows else 0.0,
        "avg_prompt_chars": round(sum(prompt_lengths) / len(prompt_lengths), 4) if prompt_lengths else 0.0,
        "max_prompt_chars": max(prompt_lengths) if prompt_lengths else 0,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    return "\n".join(
        [
            "# PrimeVul Side-Inversion Verifier Dataset",
            "",
            "This artifact converts the side-inversion review queue into a strict `accept_flip` / `reject_flip` verifier task. It defines the next verifier target; it is not a trained verifier result.",
            "",
            "## Summary",
            "",
            f"- Rows: `{summary['rows']}`",
            f"- Unique pair keys: `{summary['unique_pair_count']}`",
            f"- Accept / reject rows: `{summary['accept_flip_rows']}` / `{summary['reject_flip_rows']}`",
            f"- Accept rate: `{summary['accept_rate']}`",
            f"- Average prompt chars: `{summary['avg_prompt_chars']}`",
            f"- Max prompt chars: `{summary['max_prompt_chars']}`",
            "",
            "## Output Contract",
            "",
            "```json",
            '{"accept_flip": true, "reason_code": "evidence_supports_flip", "evidence_side": "B", "confidence": "medium"}',
            "```",
            "",
            "## Boundary",
            "",
            "Gold labels are included to define supervised targets and offline metrics. A deployment verifier must only consume the prompt fields and produce the JSON contract.",
            "",
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Build strict verifier targets from side-inversion review queue rows.")
    parser.add_argument("--queue", required=True)
    parser.add_argument("--jsonl-output", required=True)
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--summary-md", required=True)
    args = parser.parse_args()

    rows = build_rows(read_jsonl(args.queue))
    payload = {"config": vars(args), "summary": summarize(rows)}
    write_jsonl(args.jsonl_output, rows)
    write_json(args.summary_json, payload)
    output = Path(args.summary_md)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()

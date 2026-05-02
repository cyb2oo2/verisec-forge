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

from scripts.evaluate_primevul_paired_window_side_model import (
    label,
    parse_ints,
    score_rows,
    split_rows,
    train,
)
from vrf.io_utils import read_jsonl, write_json, write_jsonl


def compact_side_windows(row: dict[str, Any], side: str) -> list[dict[str, Any]]:
    windows = row.get(f"side_{side}_windows", [])
    compact = []
    for window in windows:
        compact.append(
            {
                "header": window.get("header"),
                "direction_labels": window.get("direction_labels", []),
                "risk_support": window.get("risk_support", 0),
                "safety_support": window.get("safety_support", 0),
                "removed_preview": window.get("removed_preview", [])[:4],
                "added_preview": window.get("added_preview", [])[:4],
            }
        )
    return compact


def queue_row(seed: int, rank: int, row: dict[str, Any], score: dict[str, Any]) -> dict[str, Any]:
    return {
        "seed": seed,
        "rank": rank,
        "pair_key": row["pair_key"],
        "side_model_score": round(float(score["inversion_probability"]), 6),
        "gold_invert": int(score["gold_invert"]),
        "label": row["label"],
        "is_true_inversion_candidate": row["label"] == "B",
        "side_a_id": row["side_a_id"],
        "side_b_id": row["side_b_id"],
        "side_a_probability": row["side_a_probability"],
        "side_b_probability": row["side_b_probability"],
        "probability_gap": row["probability_gap"],
        "project": row.get("project"),
        "cve": row.get("cve"),
        "changed_line_bucket": row.get("changed_line_bucket"),
        "side_a_windows": compact_side_windows(row, "a"),
        "side_b_windows": compact_side_windows(row, "b"),
        "contrastive_prompt": row.get("contrastive_prompt", ""),
    }


def build_queue(
    rows: list[dict[str, Any]],
    *,
    seeds: list[int],
    calibration_fraction: float,
    epochs: int,
    learning_rate: float,
    l2: float,
    positive_weight: float,
    feature_mode: str,
    top_k: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    queue: list[dict[str, Any]] = []
    for seed in seeds:
        train_rows, eval_rows = split_rows(rows, calibration_fraction=calibration_fraction, seed=seed)
        weights = train(
            train_rows,
            epochs=epochs,
            learning_rate=learning_rate,
            l2=l2,
            seed=seed,
            positive_weight=positive_weight,
            feature_mode=feature_mode,
        )
        scores = score_rows(eval_rows, weights, feature_mode=feature_mode)
        row_by_key = {row["pair_key"]: row for row in eval_rows}
        ordered = sorted(scores, key=lambda score: float(score["inversion_probability"]), reverse=True)[:top_k]
        for rank, score in enumerate(ordered, start=1):
            queue.append(queue_row(seed, rank, row_by_key[score["pair_key"]], score))
    return queue, summarize(queue, seeds=seeds, top_k=top_k)


def summarize(queue: list[dict[str, Any]], *, seeds: list[int], top_k: int) -> dict[str, Any]:
    by_seed: list[dict[str, Any]] = []
    for seed in seeds:
        rows = [row for row in queue if int(row["seed"]) == seed]
        true_count = sum(1 for row in rows if row["is_true_inversion_candidate"])
        by_seed.append(
            {
                "seed": seed,
                "rows": len(rows),
                "true_inversions": true_count,
                "precision": round(true_count / len(rows), 4) if rows else 0.0,
            }
        )
    true_total = sum(row["true_inversions"] for row in by_seed)
    unique_pairs = sorted({row["pair_key"] for row in queue})
    return {
        "seeds": seeds,
        "top_k": top_k,
        "rows": len(queue),
        "unique_pair_count": len(unique_pairs),
        "true_inversions": true_total,
        "precision": round(true_total / len(queue), 4) if queue else 0.0,
        "by_seed": by_seed,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# PrimeVul Side-Inversion Review Queue",
        "",
        "This artifact materializes the top-scored paired-window side-inversion candidates. It is meant as a review/verifier queue, not an automatic correction layer.",
        "",
        "## Summary",
        "",
        f"- Seeds: `{summary['seeds']}`",
        f"- Top-k per seed: `{summary['top_k']}`",
        f"- Queue rows: `{summary['rows']}`",
        f"- Unique pair keys: `{summary['unique_pair_count']}`",
        f"- True inversions: `{summary['true_inversions']}`",
        f"- Queue precision: `{summary['precision']}`",
        "",
        "## Per-Seed Precision",
        "",
        "| seed | rows | true_inversions | precision |",
        "| ---: | ---: | ---: | ---: |",
    ]
    for row in summary["by_seed"]:
        lines.append(f"| {row['seed']} | {row['rows']} | {row['true_inversions']} | {row['precision']} |")
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "The queue is selected from model scores and still includes gold labels for analysis. A future deployable verifier must evaluate these candidates on held-out pair groups without using gold labels.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a top-k side-inversion review queue from paired-window examples.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--seeds", default="7,13,42,99,123")
    parser.add_argument("--calibration-fraction", type=float, default=0.3)
    parser.add_argument("--epochs", type=int, default=80)
    parser.add_argument("--learning-rate", type=float, default=0.01)
    parser.add_argument("--l2", type=float, default=0.0001)
    parser.add_argument("--positive-weight", type=float, default=8.0)
    parser.add_argument("--feature-mode", default="numeric_text", choices=["numeric", "numeric_text"])
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--jsonl-output", required=True)
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--summary-md", required=True)
    args = parser.parse_args()

    queue, summary = build_queue(
        read_jsonl(args.input),
        seeds=parse_ints(args.seeds),
        calibration_fraction=args.calibration_fraction,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        l2=args.l2,
        positive_weight=args.positive_weight,
        feature_mode=args.feature_mode,
        top_k=args.top_k,
    )
    payload = {"config": vars(args), "summary": summary}
    write_jsonl(args.jsonl_output, queue)
    write_json(args.summary_json, payload)
    output = Path(args.summary_md)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

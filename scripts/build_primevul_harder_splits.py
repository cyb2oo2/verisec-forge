from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any

from vrf.io_utils import read_jsonl, write_json, write_jsonl


def _label(row: dict[str, Any]) -> bool:
    return bool(row.get("has_vulnerability"))


def _project(row: dict[str, Any]) -> str:
    return str(row.get("project") or "").strip()


def _split(row: dict[str, Any]) -> str:
    return str(row.get("split") or "").strip().lower()


def label_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(_label(row) for row in rows)
    return {"vulnerable": counts[True], "safe": counts[False], "total": len(rows)}


def project_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    return dict(Counter(_project(row) or "unknown" for row in rows).most_common())


def filter_candidate_split(rows: list[dict[str, Any]], candidate_split: str) -> list[dict[str, Any]]:
    if candidate_split == "any":
        return list(rows)
    return [row for row in rows if _split(row) == candidate_split]


def select_balanced_rows(
    rows: list[dict[str, Any]],
    *,
    per_label_count: int,
    seed: int,
) -> list[dict[str, Any]]:
    positives = [row for row in rows if _label(row)]
    negatives = [row for row in rows if not _label(row)]
    rng = random.Random(seed)
    rng.shuffle(positives)
    rng.shuffle(negatives)

    limit = min(len(positives), len(negatives))
    if per_label_count > 0:
        limit = min(limit, per_label_count)

    selected = positives[:limit] + negatives[:limit]
    rng.shuffle(selected)
    return selected


def build_project_disjoint(
    *,
    input_rows: list[dict[str, Any]],
    train_rows: list[dict[str, Any]],
    candidate_split: str,
    per_label_count: int,
    seed: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    train_projects = {_project(row) for row in train_rows if _project(row)}
    candidate_rows = filter_candidate_split(input_rows, candidate_split)
    project_known_rows = [row for row in candidate_rows if _project(row)]
    disjoint_rows = [row for row in project_known_rows if _project(row) not in train_projects]
    selected = select_balanced_rows(disjoint_rows, per_label_count=per_label_count, seed=seed)
    eval_projects = {_project(row) for row in selected if _project(row)}

    summary = {
        "mode": "project_disjoint",
        "candidate_split": candidate_split,
        "seed": seed,
        "per_label_count_requested": per_label_count,
        "train_reference": label_counts(train_rows),
        "input_candidates": label_counts(candidate_rows),
        "project_known_candidates": label_counts(project_known_rows),
        "project_disjoint_candidates": label_counts(disjoint_rows),
        "selected": label_counts(selected),
        "train_project_count": len(train_projects),
        "selected_project_count": len(eval_projects),
        "project_overlap_with_train": len(train_projects & eval_projects),
        "top_selected_projects": project_counts(selected),
    }
    return selected, summary


def build_paired_eval(
    *,
    input_rows: list[dict[str, Any]],
    candidate_split: str,
    per_label_count: int,
    seed: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    candidate_rows = filter_candidate_split(input_rows, candidate_split)
    selected = select_balanced_rows(candidate_rows, per_label_count=per_label_count, seed=seed)
    summary = {
        "mode": "paired_eval",
        "candidate_split": candidate_split,
        "seed": seed,
        "per_label_count_requested": per_label_count,
        "input_candidates": label_counts(candidate_rows),
        "selected": label_counts(selected),
        "selected_project_count": len({_project(row) for row in selected if _project(row)}),
        "top_selected_projects": project_counts(selected),
    }
    return selected, summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Build harder PrimeVul evaluation splits for shortcut checks.")
    parser.add_argument("--input", required=True, help="Metadata-enriched PrimeVul JSONL pool")
    parser.add_argument("--output", required=True, help="Output split JSONL")
    parser.add_argument("--summary-output", default="", help="Optional summary JSON path")
    parser.add_argument("--mode", choices=["project_disjoint", "paired_eval"], required=True)
    parser.add_argument("--train-reference", default="", help="Train JSONL used to define seen projects")
    parser.add_argument("--candidate-split", default="eval", help="Candidate split to sample from, or 'any'")
    parser.add_argument("--per-label-count", type=int, default=0, help="Rows per class; 0 uses max balanced size")
    parser.add_argument("--seed", type=int, default=13)
    args = parser.parse_args()

    input_rows = read_jsonl(args.input)
    if args.mode == "project_disjoint":
        if not args.train_reference:
            raise SystemExit("--train-reference is required for project_disjoint mode")
        selected, summary = build_project_disjoint(
            input_rows=input_rows,
            train_rows=read_jsonl(args.train_reference),
            candidate_split=args.candidate_split,
            per_label_count=args.per_label_count,
            seed=args.seed,
        )
    else:
        selected, summary = build_paired_eval(
            input_rows=input_rows,
            candidate_split=args.candidate_split,
            per_label_count=args.per_label_count,
            seed=args.seed,
        )

    write_jsonl(args.output, selected)
    summary = {"output": args.output, **summary}
    if args.summary_output:
        write_json(args.summary_output, summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

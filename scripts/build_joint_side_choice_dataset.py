from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_jsonl
from vrf.joint_reasoning import (
    build_side_choice_examples,
    build_synthetic_side_choice_examples,
    summarize_side_choice_examples,
)


def build_examples(path: Path, include_reverse: bool) -> tuple[list[dict], dict]:
    grouped: dict[str, list[dict]] = {}
    for row in read_jsonl(path):
        grouped.setdefault(str(row.get("pair_key") or row["id"]), []).append(row)
    examples: list[dict] = []
    skipped = 0
    skipped_non_complementary = 0
    for pair_key, rows in sorted(grouped.items()):
        if len(rows) != 2:
            skipped += 1
            continue
        if {bool(row.get("has_vulnerability")) for row in rows} != {False, True}:
            skipped_non_complementary += 1
            continue
        examples.extend(build_side_choice_examples(pair_key, rows, include_reverse=include_reverse))
    summary = summarize_side_choice_examples(examples)
    summary["skipped_non_pair_groups"] = skipped
    summary["skipped_non_complementary_pairs"] = skipped_non_complementary
    return examples, summary


def build_synthetic_examples(path: Path) -> tuple[list[dict], dict]:
    examples = []
    for index, row in enumerate(read_jsonl(path)):
        row = dict(row)
        row["_synthetic_instance"] = f"{index:06d}"
        examples.extend(build_synthetic_side_choice_examples(row))
    summary = summarize_side_choice_examples(examples)
    summary["synthetic_reverse_pairs"] = len(examples) // 2
    return examples, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Build symmetric pair-level side-choice datasets.")
    parser.add_argument(
        "--train-input",
        default="data/processed/secure_code_primevul_pair_diff_only_train_balanced_3000_metadata.jsonl",
    )
    parser.add_argument(
        "--eval-input",
        default="data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl",
    )
    parser.add_argument("--train-output", default="data/processed/secure_code_primevul_joint_side_choice_train_v1.jsonl")
    parser.add_argument("--eval-output", default="data/processed/secure_code_primevul_joint_side_choice_eval_v1.jsonl")
    parser.add_argument("--summary-output", default="reports/secure_code_primevul_joint_side_choice_dataset_v1.json")
    parser.add_argument("--single-orientation", action="store_true")
    args = parser.parse_args()

    train, train_summary = build_synthetic_examples(ROOT / args.train_input)
    eval_rows, eval_summary = build_examples(ROOT / args.eval_input, not args.single_orientation)
    train_pairs = {row.get("source_pair_key", row["pair_key"]) for row in train}
    eval_pairs = {row["pair_key"] for row in eval_rows}
    overlap = sorted(train_pairs & eval_pairs)
    if overlap:
        raise RuntimeError(f"train/eval pair_key overlap detected: {len(overlap)} groups")

    write_jsonl(ROOT / args.train_output, train)
    write_jsonl(ROOT / args.eval_output, eval_rows)
    summary = {
        "status": "ok",
        "scope": "primevul_joint_side_choice_dataset_v1",
        "train": train_summary,
        "eval": eval_summary,
        "pair_key_overlap": 0,
        "representation": "metadata-free Side A to Side B unified diff",
        "reverse_orientation_included": not args.single_orientation,
        "train_pair_construction": "each observed training direction plus a synthetic reversed diff",
    }
    (ROOT / args.summary_output).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

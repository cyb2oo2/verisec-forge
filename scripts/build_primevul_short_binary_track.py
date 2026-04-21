from __future__ import annotations

import argparse
import json
import random
from pathlib import Path


def _genericize_binary_row(row: dict) -> dict:
    has_vulnerability = bool(row.get("has_vulnerability", False))
    cloned = dict(row)
    cloned["vulnerability_type"] = "unknown" if has_vulnerability else "none"
    cloned["severity"] = "unknown" if has_vulnerability else "none"
    cloned["gold_evidence"] = []
    cloned["gold_explanation"] = (
        "The function contains a vulnerability-like defect and should be treated as unsafe."
        if has_vulnerability
        else "No vulnerability-like defect is labeled for this function."
    )
    cloned["gold_fix_principle"] = (
        "Remove the unsafe behavior, validate inputs, and replace fragile logic with safer handling."
        if has_vulnerability
        else "Preserve safe coding practices and avoid introducing unsafe behavior."
    )
    return cloned


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a short-function binary vulnerability track from local PrimeVul."
    )
    parser.add_argument("--input", required=True, help="Normalized PrimeVul JSONL")
    parser.add_argument("--train-output", required=True, help="Balanced train JSONL")
    parser.add_argument("--eval-output", required=True, help="Balanced eval JSONL")
    parser.add_argument("--max-code-chars", type=int, default=1500, help="Maximum function length in characters")
    parser.add_argument("--train-per-label", type=int, default=800, help="Rows per label for training")
    parser.add_argument("--eval-per-label", type=int, default=200, help="Rows per label for evaluation")
    parser.add_argument("--seed", type=int, default=17, help="Random seed")
    args = parser.parse_args()

    input_path = Path(args.input)
    train_output = Path(args.train_output)
    eval_output = Path(args.eval_output)
    train_output.parent.mkdir(parents=True, exist_ok=True)
    eval_output.parent.mkdir(parents=True, exist_ok=True)

    positives: list[dict] = []
    negatives: list[dict] = []
    with input_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("split") != "train":
                continue
            if len(row.get("code") or "") > args.max_code_chars:
                continue
            if row.get("has_vulnerability"):
                positives.append(_genericize_binary_row(row))
            else:
                negatives.append(_genericize_binary_row(row))

    rng = random.Random(args.seed)
    rng.shuffle(positives)
    rng.shuffle(negatives)

    max_eval = min(args.eval_per_label, len(positives), len(negatives))
    eval_rows = positives[:max_eval] + negatives[:max_eval]
    remaining_positives = positives[max_eval:]
    remaining_negatives = negatives[max_eval:]

    max_train = min(args.train_per_label, len(remaining_positives), len(remaining_negatives))
    train_rows = remaining_positives[:max_train] + remaining_negatives[:max_train]

    for row in eval_rows:
        row["split"] = "eval"
    for row in train_rows:
        row["split"] = "train"

    rng.shuffle(eval_rows)
    rng.shuffle(train_rows)

    with train_output.open("w", encoding="utf-8") as handle:
        for row in train_rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    with eval_output.open("w", encoding="utf-8") as handle:
        for row in eval_rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(
        json.dumps(
            {
                "train_rows": len(train_rows),
                "eval_rows": len(eval_rows),
                "max_code_chars": args.max_code_chars,
                "train_output": str(train_output),
                "eval_output": str(eval_output),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

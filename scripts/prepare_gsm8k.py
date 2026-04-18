from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from datasets import Dataset, load_dataset
from tqdm.auto import tqdm

from vrf.io_utils import ensure_parent


ANSWER_MARKER = "####"
NUMERIC_PATTERN = re.compile(r"-?\d[\d,]*(?:\.\d+)?")
ANNOTATION_PATTERN = re.compile(r"<<[^<>]+>>")
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "huggingface" / "datasets" / "openai___gsm8k" / "main" / "0.0.0"


def extract_answer_parts(answer_text: str) -> tuple[str, str]:
    if ANSWER_MARKER not in answer_text:
        reasoning = answer_text.strip()
        final_answer = ""
    else:
        reasoning, final_raw = answer_text.rsplit(ANSWER_MARKER, 1)
        reasoning = reasoning.strip()
        final_raw = final_raw.strip()
        matches = NUMERIC_PATTERN.findall(final_raw)
        final_answer = matches[-1].replace(",", "") if matches else final_raw
    reasoning = ANNOTATION_PATTERN.sub("", reasoning)
    reasoning = re.sub(r"[ \t]+", " ", reasoning)
    reasoning = re.sub(r" *\n *", "\n", reasoning).strip()
    return reasoning, final_answer


def make_train_row(example: dict[str, str], idx: int) -> dict[str, str]:
    reasoning, final_answer = extract_answer_parts(example["answer"])
    response = json.dumps(
        {
            "reasoning": reasoning,
            "final_answer": final_answer,
        },
        ensure_ascii=False,
    )
    return {
        "id": f"gsm8k-train-{idx:05d}",
        "prompt": example["question"].strip(),
        "gold_answer": final_answer,
        "split": "train",
        "difficulty": "gsm8k",
        "source": "openai/gsm8k",
        "response": response,
    }


def make_eval_row(example: dict[str, str], idx: int) -> dict[str, str]:
    _, final_answer = extract_answer_parts(example["answer"])
    return {
        "id": f"gsm8k-test-{idx:05d}",
        "prompt": example["question"].strip(),
        "gold_answer": final_answer,
        "split": "test",
        "difficulty": "gsm8k",
        "source": "openai/gsm8k",
    }


def load_gsm8k_from_local_cache(cache_root: Path) -> tuple[Dataset, Dataset] | None:
    if not cache_root.exists():
        return None
    revisions = sorted([path for path in cache_root.iterdir() if path.is_dir()], reverse=True)
    for revision_dir in revisions:
        train_file = revision_dir / "gsm8k-train.arrow"
        eval_file = revision_dir / "gsm8k-test.arrow"
        if train_file.exists() and eval_file.exists():
            return Dataset.from_file(str(train_file)), Dataset.from_file(str(eval_file))
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare GSM8K for Verifiable Reasoning Forge")
    parser.add_argument("--train-output", default="data/processed/train_sft_gsm8k_structured.jsonl")
    parser.add_argument("--eval-output", default="data/processed/eval_gsm8k.jsonl")
    parser.add_argument("--train-limit", type=int, default=0)
    parser.add_argument("--eval-limit", type=int, default=0)
    parser.add_argument("--cache-root", default=str(DEFAULT_CACHE_DIR))
    args = parser.parse_args()

    local_cache = load_gsm8k_from_local_cache(Path(args.cache_root))
    if local_cache is not None:
        train_split, eval_split = local_cache
    else:
        dataset = load_dataset("openai/gsm8k", "main")
        train_split = dataset["train"]
        eval_split = dataset["test"]

    if args.train_limit > 0:
        train_split = train_split.select(range(min(args.train_limit, len(train_split))))
    if args.eval_limit > 0:
        eval_split = eval_split.select(range(min(args.eval_limit, len(eval_split))))

    train_output = ensure_parent(Path(args.train_output))
    eval_output = ensure_parent(Path(args.eval_output))

    train_count = 0
    with train_output.open("w", encoding="utf-8") as handle:
        for idx, example in enumerate(tqdm(train_split, desc="Preparing GSM8K train", total=len(train_split))):
            handle.write(json.dumps(make_train_row(example, idx), ensure_ascii=False) + "\n")
            train_count += 1

    eval_count = 0
    with eval_output.open("w", encoding="utf-8") as handle:
        for idx, example in enumerate(tqdm(eval_split, desc="Preparing GSM8K eval", total=len(eval_split))):
            handle.write(json.dumps(make_eval_row(example, idx), ensure_ascii=False) + "\n")
            eval_count += 1

    print(
        json.dumps(
            {
                "train_rows": train_count,
                "eval_rows": eval_count,
                "train_output": args.train_output,
                "eval_output": args.eval_output,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

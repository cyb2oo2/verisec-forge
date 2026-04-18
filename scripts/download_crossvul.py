from __future__ import annotations

import argparse
import json
from pathlib import Path

from datasets import load_dataset


def build_prompt(language: str, code: str) -> str:
    return (
        f"Analyze the following {language} code for defensive security issues and return JSON only.\n\n"
        f"code:\n{code}"
    )


def normalized_rows(record: dict, index: int) -> list[dict]:
    cwe_id = str(record.get("cwe_id", "none")).strip().lower().replace("_", "-")
    if cwe_id.startswith("cwe") and not cwe_id.startswith("cwe-"):
        cwe_id = cwe_id.replace("cwe", "cwe-", 1)

    language = record.get("language") or record.get("language_dir") or "unknown"
    source = record.get("source", "crossvul")
    context = record.get("cwe_description")
    vulnerable_code = record.get("vulnerable_code", "")
    fixed_code = record.get("fixed_code", "")
    split = "eval" if index % 10 == 0 else "train"
    difficulty = "unknown"
    pair_id = str(record.get("file_pair_id", index))

    vulnerable_row = {
        "id": f"crossvul-vuln-{pair_id}",
        "task_type": "weakness_identification",
        "language": language,
        "prompt": build_prompt(language, vulnerable_code),
        "code": vulnerable_code,
        "diff": None,
        "context": context,
        "split": split,
        "difficulty": difficulty,
        "source": source,
        "has_vulnerability": True,
        "vulnerability_type": cwe_id or "none",
        "severity": "unknown",
        "gold_fix_choice": None,
        "response": None,
        "chosen": None,
        "rejected": None,
        "score": None,
    }

    fixed_row = {
        "id": f"crossvul-fixed-{pair_id}",
        "task_type": "weakness_identification",
        "language": language,
        "prompt": build_prompt(language, fixed_code),
        "code": fixed_code,
        "diff": None,
        "context": context,
        "split": split,
        "difficulty": difficulty,
        "source": source,
        "has_vulnerability": False,
        "vulnerability_type": "none",
        "severity": "none",
        "gold_fix_choice": None,
        "response": None,
        "chosen": None,
        "rejected": None,
        "score": None,
    }
    return [vulnerable_row, fixed_row]


def main() -> None:
    parser = argparse.ArgumentParser(description="Download and normalize CrossVul into VeriSec Forge JSONL.")
    parser.add_argument("--dataset", default="hitoshura25/crossvul", help="HF dataset name")
    parser.add_argument("--output-raw", default="data/raw/crossvul_train_raw.jsonl", help="Local raw JSONL path")
    parser.add_argument(
        "--output-normalized",
        default="data/processed/secure_code_crossvul_normalized.jsonl",
        help="Local normalized JSONL path",
    )
    parser.add_argument("--limit", type=int, default=0, help="Optional row limit for fast experiments (0 = full stream)")
    args = parser.parse_args()

    raw_path = Path(args.output_raw)
    normalized_path = Path(args.output_normalized)
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    normalized_path.parent.mkdir(parents=True, exist_ok=True)

    dataset = load_dataset(args.dataset, streaming=True)
    split_name = list(dataset.keys())[0]
    split = dataset[split_name]

    raw_count = 0
    normalized_count = 0
    with raw_path.open("w", encoding="utf-8") as raw_handle, normalized_path.open("w", encoding="utf-8") as normalized_handle:
        for index, record in enumerate(split):
            if args.limit and index >= args.limit:
                break
            raw_handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            raw_count += 1
            for row in normalized_rows(record, index):
                normalized_handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                normalized_count += 1

    print(
        json.dumps(
            {
                "dataset": args.dataset,
                "raw_rows": raw_count,
                "normalized_rows": normalized_count,
                "raw_path": str(raw_path),
                "normalized_path": str(normalized_path),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

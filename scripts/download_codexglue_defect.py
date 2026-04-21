from __future__ import annotations

import argparse
import json
from pathlib import Path

from datasets import load_dataset


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download CodeXGLUE defect detection from Hugging Face and save local JSONL splits."
    )
    parser.add_argument(
        "--dataset",
        default="google/code_x_glue_cc_defect_detection",
        help="HF dataset id",
    )
    parser.add_argument(
        "--output-dir",
        default="data/raw/codexglue_defect",
        help="Directory to write split JSONL files",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional per-split row limit for quick smoke runs",
    )
    args = parser.parse_args()

    ds = load_dataset(args.dataset)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    summary: dict[str, int] = {}
    for split_name, split in ds.items():
        output_path = output_dir / f"{split_name}.jsonl"
        count = 0
        with output_path.open("w", encoding="utf-8") as handle:
            for row in split:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                count += 1
                if args.limit and count >= args.limit:
                    break
        summary[split_name] = count

    print(json.dumps({"dataset": args.dataset, "output_dir": str(output_dir), "splits": summary}, indent=2))


if __name__ == "__main__":
    main()

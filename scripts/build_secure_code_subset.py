from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a capped secure-code subset with per-task limits.")
    parser.add_argument("--input", required=True, help="Normalized benchmark JSONL")
    parser.add_argument("--output", required=True, help="Subset JSONL output path")
    parser.add_argument("--per-task-limit", type=int, default=100, help="Maximum examples per task_type")
    parser.add_argument("--split", default="", help="Optional split filter")
    parser.add_argument(
        "--balance-by-vulnerability",
        action="store_true",
        help="Keep a balanced number of vulnerable and safe examples within each task_type.",
    )
    parser.add_argument(
        "--per-label-limit",
        type=int,
        default=0,
        help="Optional explicit cap per has_vulnerability label when balancing is enabled.",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    kept: list[dict] = []
    counts: dict[str, int] = defaultdict(int)
    if args.balance_by_vulnerability:
        buckets: dict[tuple[str, bool], list[dict]] = defaultdict(list)
        with input_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                if args.split and row.get("split", "") != args.split:
                    continue
                task_type = row.get("task_type", "unknown")
                label = bool(row.get("has_vulnerability", False))
                buckets[(task_type, label)].append(row)

        task_types = sorted({task_type for task_type, _ in buckets.keys()})
        for task_type in task_types:
            positive_rows = buckets.get((task_type, True), [])
            negative_rows = buckets.get((task_type, False), [])
            if args.per_label_limit:
                label_limit = args.per_label_limit
            else:
                label_limit = min(len(positive_rows), len(negative_rows), max(1, args.per_task_limit // 2))

            for row in positive_rows[:label_limit]:
                kept.append(row)
                counts[task_type] += 1
            for row in negative_rows[:label_limit]:
                kept.append(row)
                counts[task_type] += 1
    else:
        with input_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                if args.split and row.get("split", "") != args.split:
                    continue
                task_type = row.get("task_type", "unknown")
                if counts[task_type] >= args.per_task_limit:
                    continue
                kept.append(row)
                counts[task_type] += 1

    with output_path.open("w", encoding="utf-8") as handle:
        for row in kept:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(json.dumps({"rows": len(kept), "counts": counts, "output_path": str(output_path)}, indent=2))


if __name__ == "__main__":
    main()

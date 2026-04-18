from __future__ import annotations

import argparse
import json
import random
from pathlib import Path


def _load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a held-out balanced PrimeVul eval set by excluding training ids."
    )
    parser.add_argument("--normalized", required=True, help="Normalized PrimeVul JSONL")
    parser.add_argument("--exclude", required=True, help="JSONL file whose ids should be excluded")
    parser.add_argument("--output", required=True, help="Balanced holdout eval JSONL")
    parser.add_argument(
        "--per-label-count",
        type=int,
        default=500,
        help="Number of vulnerable and safe examples to keep",
    )
    parser.add_argument("--seed", type=int, default=17, help="Sampling seed")
    args = parser.parse_args()

    normalized_path = Path(args.normalized)
    exclude_path = Path(args.exclude)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    excluded_ids = {row["id"] for row in _load_jsonl(exclude_path)}
    rows = [row for row in _load_jsonl(normalized_path) if row.get("split") == "train" and row["id"] not in excluded_ids]

    vulnerable_rows = [row for row in rows if bool(row.get("has_vulnerability"))]
    safe_rows = [row for row in rows if not bool(row.get("has_vulnerability"))]

    rng = random.Random(args.seed)
    rng.shuffle(vulnerable_rows)
    rng.shuffle(safe_rows)

    per_label_count = min(args.per_label_count, len(vulnerable_rows), len(safe_rows))
    kept = vulnerable_rows[:per_label_count] + safe_rows[:per_label_count]
    kept.sort(key=lambda row: row["id"])

    with output_path.open("w", encoding="utf-8") as handle:
        for row in kept:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(
        json.dumps(
            {
                "output_path": str(output_path),
                "excluded_ids": len(excluded_ids),
                "available_vulnerable": len(vulnerable_rows),
                "available_safe": len(safe_rows),
                "kept_total": len(kept),
                "kept_per_label": per_label_count,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

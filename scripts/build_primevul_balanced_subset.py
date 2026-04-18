from __future__ import annotations

import argparse
import json
import random
from pathlib import Path


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a balanced PrimeVul subset from an existing JSONL split.")
    parser.add_argument("--input", required=True, help="Input JSONL")
    parser.add_argument("--output", required=True, help="Output JSONL")
    parser.add_argument("--per-label-count", type=int, required=True, help="Rows to keep for each label")
    parser.add_argument("--seed", type=int, default=17)
    args = parser.parse_args()

    rows = load_jsonl(Path(args.input))
    vulnerable = [row for row in rows if bool(row.get("has_vulnerability"))]
    safe = [row for row in rows if not bool(row.get("has_vulnerability"))]

    rng = random.Random(args.seed)
    rng.shuffle(vulnerable)
    rng.shuffle(safe)

    keep = min(args.per_label_count, len(vulnerable), len(safe))
    kept = vulnerable[:keep] + safe[:keep]
    kept.sort(key=lambda row: row["id"])

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for row in kept:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(
        json.dumps(
            {
                "input_rows": len(rows),
                "kept_total": len(kept),
                "kept_per_label": keep,
                "output_path": str(output_path),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

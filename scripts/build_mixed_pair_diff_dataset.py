from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def label_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(int(bool(row.get("has_vulnerability"))) for row in rows)
    return {"safe": counts[0], "vulnerable": counts[1]}


def source_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    return dict(Counter(str(row.get("source_dataset") or "unknown") for row in rows))


def prefixed_row(row: dict[str, Any], *, source: str, index: int) -> dict[str, Any]:
    copied = dict(row)
    original_id = str(copied.get("id"))
    original_pair_key = str(copied.get("pair_key", original_id))
    copied["source_original_id"] = original_id
    copied["id"] = f"{source}:{index:06d}:{original_id}"
    copied["pair_key"] = f"{source}:{original_pair_key}"
    copied["source_dataset"] = source
    return copied


def build_mixed_rows(inputs: list[tuple[str, Path]], *, seed: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    input_summaries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_pair_keys: set[str] = set()

    for source, path in inputs:
        source_rows = [prefixed_row(row, source=source, index=idx) for idx, row in enumerate(read_jsonl(path))]
        duplicate_ids = len(source_rows) - len({str(row["id"]) for row in source_rows})
        rows.extend(source_rows)
        input_summaries.append(
            {
                "source_dataset": source,
                "path": str(path.relative_to(ROOT) if path.is_relative_to(ROOT) else path),
                "rows": len(source_rows),
                "pair_keys": len({str(row.get("pair_key")) for row in source_rows}),
                "labels": label_counts(source_rows),
                "duplicate_ids_after_prefix": duplicate_ids,
            }
        )
        seen_ids.update(str(row["id"]) for row in source_rows)
        seen_pair_keys.update(str(row.get("pair_key")) for row in source_rows)

    rng = random.Random(seed)
    rng.shuffle(rows)
    summary = {
        "scope": "mixed_pair_diff_dataset",
        "seed": seed,
        "inputs": input_summaries,
        "rows": len(rows),
        "unique_ids": len(seen_ids),
        "unique_pair_keys": len(seen_pair_keys),
        "labels": label_counts(rows),
        "source_counts": source_counts(rows),
    }
    return rows, summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a mixed-source paired-diff classifier dataset.")
    parser.add_argument(
        "--input",
        action="append",
        nargs=2,
        metavar=("SOURCE", "PATH"),
        required=True,
        help="Source name plus JSONL path. Can be passed multiple times.",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    inputs = [(source, ROOT / path) for source, path in args.input]
    rows, summary = build_mixed_rows(inputs, seed=args.seed)
    write_jsonl(ROOT / args.output, rows)
    summary_path = ROOT / args.summary_output
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

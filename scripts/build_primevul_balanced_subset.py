from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from vrf.io_utils import read_jsonl, write_jsonl


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a balanced PrimeVul subset from normalized secure-code rows.")
    parser.add_argument("--input", required=True, help="Normalized PrimeVul JSONL path")
    parser.add_argument("--output", required=True, help="Balanced subset JSONL output path")
    parser.add_argument("--split", default="train", help="Split to sample from (default: train)")
    parser.add_argument("--per-class", type=int, required=True, help="Number of vulnerable and safe rows to sample")
    parser.add_argument("--seed", type=int, default=17, help="Sampling seed")
    parser.add_argument("--exclude", default=None, help="Optional JSONL path whose ids should be excluded")
    args = parser.parse_args()

    excluded_ids: set[str] = set()
    if args.exclude:
        excluded_ids = {str(row["id"]) for row in read_jsonl(args.exclude)}

    rows = [
        row
        for row in read_jsonl(args.input)
        if str(row.get("split", "")) == args.split and str(row.get("id", "")) not in excluded_ids
    ]
    vulnerable = [row for row in rows if bool(row.get("has_vulnerability"))]
    safe = [row for row in rows if not bool(row.get("has_vulnerability"))]

    if len(vulnerable) < args.per_class or len(safe) < args.per_class:
        raise ValueError(
            f"Requested per-class={args.per_class}, but only have "
            f"{len(vulnerable)} vulnerable and {len(safe)} safe rows in split={args.split!r} after exclusions."
        )

    rng = random.Random(args.seed)
    sampled = rng.sample(vulnerable, args.per_class) + rng.sample(safe, args.per_class)
    rng.shuffle(sampled)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(output_path, sampled)

    print(
        json.dumps(
            {
                "input": args.input,
                "output": str(output_path),
                "split": args.split,
                "per_class": args.per_class,
                "rows": len(sampled),
                "vulnerable": args.per_class,
                "safe": args.per_class,
                "excluded_ids": len(excluded_ids),
                "seed": args.seed,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

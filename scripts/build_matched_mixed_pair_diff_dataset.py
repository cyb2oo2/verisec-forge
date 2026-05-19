from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_primevul_directional_recall_recovery_dataset import changed_line_bucket


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
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


def prompt_lengths(rows: list[dict[str, Any]]) -> dict[str, int]:
    lengths = sorted(len(str(row.get("pair_text") or "")) for row in rows)
    if not lengths:
        return {"p50": 0, "p90": 0, "p99": 0, "max": 0}
    return {
        "p50": lengths[int((len(lengths) - 1) * 0.50)],
        "p90": lengths[int((len(lengths) - 1) * 0.90)],
        "p99": lengths[int((len(lengths) - 1) * 0.99)],
        "max": lengths[-1],
    }


def prefixed_row(row: dict[str, Any], *, source: str, index: int) -> dict[str, Any]:
    copied = dict(row)
    original_id = str(copied.get("id"))
    original_pair_key = str(copied.get("pair_key", original_id))
    if "changed_line_bucket" not in copied:
        changed_lines, bucket = changed_line_bucket(str(copied.get("pair_text") or copied.get("prompt") or ""))
        copied["changed_lines"] = changed_lines
        copied["changed_line_bucket"] = bucket
    copied["source_original_id"] = original_id
    copied["id"] = f"{source}:{index:06d}:{original_id}"
    copied["pair_key"] = f"{source}:{original_pair_key}"
    copied["source_dataset"] = source
    return copied


def sample_balanced_short_rows(
    rows: list[dict[str, Any]],
    *,
    per_label: int,
    max_chars: int,
    seed: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rng = random.Random(seed)
    eligible = [row for row in rows if len(str(row.get("pair_text") or "")) <= max_chars]
    by_label = {
        label: [row for row in eligible if int(bool(row.get("has_vulnerability"))) == label]
        for label in [0, 1]
    }
    for label_rows in by_label.values():
        rng.shuffle(label_rows)
    safe = by_label[0][:per_label]
    vulnerable = by_label[1][:per_label]
    if len(safe) < per_label or len(vulnerable) < per_label:
        raise ValueError(
            f"Not enough short PrimeVul rows for per_label={per_label}: "
            f"safe={len(safe)} vulnerable={len(vulnerable)} max_chars={max_chars}"
        )
    sampled = safe + vulnerable
    rng.shuffle(sampled)
    return sampled, {
        "eligible_rows": len(eligible),
        "eligible_labels": label_counts(eligible),
        "sampled_rows": len(sampled),
        "sampled_labels": label_counts(sampled),
        "max_chars": max_chars,
    }


def build_dataset(
    *,
    prime_rows: list[dict[str, Any]],
    delta_rows: list[dict[str, Any]],
    prime_per_label: int,
    max_prime_chars: int,
    seed: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    prime_sample, prime_summary = sample_balanced_short_rows(
        prime_rows,
        per_label=prime_per_label,
        max_chars=max_prime_chars,
        seed=seed,
    )
    mixed = [
        *(prefixed_row(row, source="primevul_time_short", index=idx) for idx, row in enumerate(prime_sample)),
        *(prefixed_row(row, source="deltasecommits", index=idx) for idx, row in enumerate(delta_rows)),
    ]
    random.Random(seed).shuffle(mixed)
    source_counts = Counter(str(row["source_dataset"]) for row in mixed)
    bucket_counts = Counter(str(row.get("changed_line_bucket") or "unknown") for row in mixed)
    summary = {
        "scope": "matched_mixed_pair_diff_dataset",
        "seed": seed,
        "rows": len(mixed),
        "unique_ids": len({str(row["id"]) for row in mixed}),
        "unique_pair_keys": len({str(row.get("pair_key")) for row in mixed}),
        "labels": label_counts(mixed),
        "source_counts": dict(source_counts),
        "changed_line_buckets": dict(sorted(bucket_counts.items())),
        "prompt_lengths": prompt_lengths(mixed),
        "prime_sampling": prime_summary,
        "delta_input": {
            "rows": len(delta_rows),
            "labels": label_counts(delta_rows),
            "prompt_lengths": prompt_lengths(delta_rows),
        },
    }
    return mixed, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a short, source-matched PrimeVul+Delta paired-diff training dataset.")
    parser.add_argument("--prime-train", default="data/processed/secure_code_primevul_pair_diff_time_train_le2020_balanced_6000_metadata.jsonl")
    parser.add_argument("--delta-train", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_train_metadata.jsonl")
    parser.add_argument("--prime-per-label", type=int, default=1307)
    parser.add_argument("--max-prime-chars", type=int, default=8192)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", default="data/processed/secure_code_matched_mixed_primevul_time_short_deltasecommits_pair_diff_train_metadata.jsonl")
    parser.add_argument("--summary-output", default="reports/secure_code_matched_mixed_primevul_time_short_deltasecommits_pair_diff_train_summary_v1.json")
    args = parser.parse_args()

    rows, summary = build_dataset(
        prime_rows=read_jsonl(ROOT / args.prime_train),
        delta_rows=read_jsonl(ROOT / args.delta_train),
        prime_per_label=args.prime_per_label,
        max_prime_chars=args.max_prime_chars,
        seed=args.seed,
    )
    write_jsonl(ROOT / args.output, rows)
    summary_path = ROOT / args.summary_output
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

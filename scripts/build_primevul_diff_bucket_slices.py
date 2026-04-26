from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.analyze_primevul_diff_failures import _diff_stats, _length_bucket
from vrf.io_utils import read_jsonl, write_json, write_jsonl

EDGE_BUCKETS = {"00-02", "26+"}


def add_bucket(row: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(row)
    stats = _diff_stats(str(row.get("pair_text") or row.get("prompt") or ""))
    enriched.update(stats)
    enriched["changed_line_bucket"] = _length_bucket(stats["changed_lines"])
    return enriched


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_bucket: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        bucket = str(row["changed_line_bucket"])
        label = "vulnerable" if bool(row.get("has_vulnerability")) else "safe"
        by_bucket[bucket][label] += 1
        by_bucket[bucket]["total"] += 1
    return {
        bucket: {
            "total": int(counts["total"]),
            "vulnerable": int(counts["vulnerable"]),
            "safe": int(counts["safe"]),
        }
        for bucket, counts in sorted(by_bucket.items())
    }


def build_bucket_eval_slices(
    rows: list[dict[str, Any]],
    *,
    output_dir: Path,
    prefix: str,
) -> dict[str, Any]:
    by_bucket: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_bucket[str(row["changed_line_bucket"])].append(row)

    outputs: dict[str, Any] = {}
    for bucket, bucket_rows in sorted(by_bucket.items()):
        safe_bucket = bucket.replace("+", "plus").replace("-", "_")
        output_path = output_dir / f"{prefix}_{safe_bucket}.jsonl"
        write_jsonl(output_path, bucket_rows)
        outputs[bucket] = {
            "path": str(output_path),
            "total": len(bucket_rows),
            "vulnerable": sum(1 for row in bucket_rows if bool(row.get("has_vulnerability"))),
            "safe": sum(1 for row in bucket_rows if not bool(row.get("has_vulnerability"))),
        }
    return outputs


def sample_balanced(
    rows: list[dict[str, Any]],
    *,
    per_label_count: int,
    rng: random.Random,
    allow_replacement: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    positives = [row for row in rows if bool(row.get("has_vulnerability"))]
    negatives = [row for row in rows if not bool(row.get("has_vulnerability"))]
    rng.shuffle(positives)
    rng.shuffle(negatives)

    def draw(pool: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if len(pool) >= per_label_count:
            return pool[:per_label_count]
        if not allow_replacement:
            return pool
        return pool + [rng.choice(pool) for _ in range(per_label_count - len(pool))]

    selected = draw(positives) + draw(negatives)
    rng.shuffle(selected)
    return selected, {
        "per_label_requested": per_label_count,
        "available_vulnerable": len(positives),
        "available_safe": len(negatives),
        "replacement_used": allow_replacement and (len(positives) < per_label_count or len(negatives) < per_label_count),
    }


def build_edge_focused_train(
    rows: list[dict[str, Any]],
    *,
    total_count: int,
    edge_share: float,
    seed: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rng = random.Random(seed)
    per_label_total = total_count // 2
    per_label_edge = int(per_label_total * edge_share)
    per_label_background = per_label_total - per_label_edge

    edge_rows = [row for row in rows if row["changed_line_bucket"] in EDGE_BUCKETS]
    background_rows = [row for row in rows if row["changed_line_bucket"] not in EDGE_BUCKETS]
    edge_selected, edge_sampling = sample_balanced(
        edge_rows,
        per_label_count=per_label_edge,
        rng=rng,
        allow_replacement=True,
    )
    background_selected, background_sampling = sample_balanced(
        background_rows,
        per_label_count=per_label_background,
        rng=rng,
        allow_replacement=True,
    )

    selected = edge_selected + background_selected
    rng.shuffle(selected)
    summary = {
        "requested_total_count": total_count,
        "actual_total_count": len(selected),
        "edge_share_requested": edge_share,
        "seed": seed,
        "edge_buckets": sorted(EDGE_BUCKETS),
        "edge_sampling": edge_sampling,
        "background_sampling": background_sampling,
        "edge_selected": summarize(edge_selected),
        "background_selected": summarize(background_selected),
        "selected": summarize(selected),
    }
    return selected, summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Build PrimeVul diff changed-line bucket slices and edge-focused train set.")
    parser.add_argument(
        "--train",
        default="data/processed/secure_code_primevul_pair_diff_only_train_balanced_3000_metadata.jsonl",
    )
    parser.add_argument(
        "--eval",
        default="data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl",
    )
    parser.add_argument("--output-dir", default="data/processed/primevul_diff_bucket_slices")
    parser.add_argument("--summary-output", default="reports/secure_code_primevul_pair_diff_bucket_slices_summary.json")
    parser.add_argument("--focused-train-output", default="data/processed/secure_code_primevul_pair_diff_edge_focus_train_balanced_3000_metadata.jsonl")
    parser.add_argument("--focused-total-count", type=int, default=3000)
    parser.add_argument("--edge-share", type=float, default=0.6)
    parser.add_argument("--seed", type=int, default=23)
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    train_rows = [add_bucket(row) for row in read_jsonl(args.train)]
    eval_rows = [add_bucket(row) for row in read_jsonl(args.eval)]

    focused_train, focused_summary = build_edge_focused_train(
        train_rows,
        total_count=args.focused_total_count,
        edge_share=args.edge_share,
        seed=args.seed,
    )
    write_jsonl(args.focused_train_output, focused_train)

    payload = {
        "train_input": args.train,
        "eval_input": args.eval,
        "focused_train_output": args.focused_train_output,
        "train_summary": summarize(train_rows),
        "eval_summary": summarize(eval_rows),
        "eval_slice_outputs": build_bucket_eval_slices(eval_rows, output_dir=output_dir, prefix="eval"),
        "focused_train_summary": focused_summary,
    }
    write_json(args.summary_output, payload)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vrf.io_utils import read_jsonl, write_json, write_jsonl


DIFF_MARKER = "Unified diff:\n"


def stable_text(value: object) -> str:
    return str(value or "").strip()


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def diff_body(row: dict[str, Any]) -> str:
    text = stable_text(row.get("pair_text"))
    if DIFF_MARKER in text:
        return text.split(DIFF_MARKER, 1)[1]
    return text


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def field_overlap(train_rows: list[dict[str, Any]], eval_rows: list[dict[str, Any]], field: str) -> dict[str, Any]:
    train_values = {stable_text(row.get(field)) for row in train_rows if stable_text(row.get(field))}
    eval_values = {stable_text(row.get(field)) for row in eval_rows if stable_text(row.get(field))}
    overlap = sorted(train_values & eval_values)
    return {
        "field": field,
        "train_unique": len(train_values),
        "eval_unique": len(eval_values),
        "overlap_count": len(overlap),
        "overlap_examples": overlap[:10],
    }


def exact_hash_overlap(
    train_rows: list[dict[str, Any]],
    eval_rows: list[dict[str, Any]],
    *,
    text_getter,
) -> dict[str, Any]:
    train_hashes: dict[str, list[str]] = {}
    for row in train_rows:
        train_hashes.setdefault(sha256_text(text_getter(row)), []).append(stable_text(row.get("id")))

    overlaps: list[dict[str, Any]] = []
    risky_eval_ids: list[str] = []
    for row in eval_rows:
        digest = sha256_text(text_getter(row))
        if digest in train_hashes:
            risky_eval_ids.append(stable_text(row.get("id")))
            overlaps.append(
                {
                    "eval_id": row.get("id"),
                    "train_ids": train_hashes[digest][:5],
                    "hash": digest,
                }
            )

    return {
        "overlap_count": len(overlaps),
        "overlap_examples": overlaps[:10],
        "risky_eval_ids": risky_eval_ids,
    }


def token_signature(text: str, *, max_tokens: int = 256) -> str:
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+|==|!=|<=|>=|[-+*/%&|^~<>]=?|[{}()[\].,;:]", text)
    return " ".join(tokens[:max_tokens])


def near_duplicate_scan(
    train_rows: list[dict[str, Any]],
    eval_rows: list[dict[str, Any]],
    *,
    threshold: float,
    max_examples: int,
) -> dict[str, Any]:
    train_by_pair_key: dict[str, list[tuple[str, str]]] = {}
    for row in train_rows:
        key = stable_text(row.get("pair_key"))
        train_by_pair_key.setdefault(key, []).append((stable_text(row.get("id")), token_signature(diff_body(row))))

    matches: list[dict[str, Any]] = []
    risky_eval_ids: list[str] = []
    max_ratio = 0.0
    for row in eval_rows:
        key = stable_text(row.get("pair_key"))
        eval_sig = token_signature(diff_body(row))
        candidates = train_by_pair_key.get(key, [])
        for train_id, train_sig in candidates:
            if not eval_sig and not train_sig:
                ratio = 1.0
            else:
                ratio = SequenceMatcher(a=train_sig, b=eval_sig, autojunk=False).ratio()
            max_ratio = max(max_ratio, ratio)
            if ratio >= threshold:
                risky_eval_ids.append(stable_text(row.get("id")))
                matches.append(
                    {
                        "eval_id": row.get("id"),
                        "train_id": train_id,
                        "pair_key": key,
                        "similarity": round(ratio, 4),
                    }
                )
                if len(matches) >= max_examples:
                    break
        if len(matches) >= max_examples:
            break

    return {
        "threshold": threshold,
        "match_count_at_or_above_threshold_limited": len(matches),
        "max_similarity_seen_within_shared_pair_keys": round(max_ratio, 4),
        "examples": matches,
        "risky_eval_ids": sorted(set(risky_eval_ids)),
        "note": "Near-duplicate scan is restricted to shared pair_key candidates for speed and interpretability.",
    }


def pair_key_label_counts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counter = Counter(stable_text(row.get("pair_key")) for row in rows if stable_text(row.get("pair_key")))
    duplicates = {key: count for key, count in counter.items() if count > 1}
    return {
        "unique_pair_keys": len(counter),
        "duplicate_pair_key_count": len(duplicates),
        "duplicate_pair_key_examples": dict(list(duplicates.items())[:10]),
    }


def build_report(train_rows: list[dict[str, Any]], eval_rows: list[dict[str, Any]], *, threshold: float) -> dict[str, Any]:
    fields = ["id", "pair_key", "pair_counterpart_id", "func_hash", "file_hash", "commit_id", "cve", "project"]
    exact_pair_text = exact_hash_overlap(train_rows, eval_rows, text_getter=lambda row: stable_text(row.get("pair_text")))
    exact_normalized_diff = exact_hash_overlap(
        train_rows,
        eval_rows,
        text_getter=lambda row: normalize_whitespace(diff_body(row)),
    )
    near_duplicate_diff = near_duplicate_scan(
        train_rows,
        eval_rows,
        threshold=threshold,
        max_examples=20,
    )
    risky_eval_ids = sorted(
        set(exact_pair_text["risky_eval_ids"])
        | set(exact_normalized_diff["risky_eval_ids"])
        | set(near_duplicate_diff["risky_eval_ids"])
    )
    return {
        "train_rows": len(train_rows),
        "eval_rows": len(eval_rows),
        "train_pair_key_summary": pair_key_label_counts(train_rows),
        "eval_pair_key_summary": pair_key_label_counts(eval_rows),
        "field_overlaps": [field_overlap(train_rows, eval_rows, field) for field in fields],
        "exact_pair_text_overlap": exact_pair_text,
        "exact_normalized_diff_overlap": exact_normalized_diff,
        "near_duplicate_diff_scan": near_duplicate_diff,
        "risky_eval_ids": risky_eval_ids,
        "risky_eval_count": len(risky_eval_ids),
        "filtered_eval_rows": len(eval_rows) - len(risky_eval_ids),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Check PrimeVul paired train/eval overlap for diff-style experiments.")
    parser.add_argument("--train", required=True)
    parser.add_argument("--eval", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--filtered-eval-output", default="")
    parser.add_argument("--near-threshold", type=float, default=0.95)
    args = parser.parse_args()

    train_rows = read_jsonl(args.train)
    eval_rows = read_jsonl(args.eval)
    report = build_report(train_rows, eval_rows, threshold=args.near_threshold)
    if args.filtered_eval_output:
        risky_eval_ids = set(report["risky_eval_ids"])
        filtered_eval_rows = [row for row in eval_rows if stable_text(row.get("id")) not in risky_eval_ids]
        write_jsonl(args.filtered_eval_output, filtered_eval_rows)
        report["filtered_eval_output"] = args.filtered_eval_output
    write_json(args.output, report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

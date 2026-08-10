"""Audit training sets for evaluation content that entered under a different key.

Key-based held-out exclusion is sound only when every source shares one key
namespace. PatchEval, DeltaSecommits and CrossVul do not: they assign several keys
to identical content, so a pair held out under one key can re-enter training under
another. ``scripts/build_prose_native_training_set.py`` now filters on
``pair_content_fingerprint`` as well as ``pair_key``; this script is the
independent check on that filter, and the tool that found the original leak.

It re-derives fingerprints from the source pools rather than trusting any builder
summary, then reports, per training set:

* ``v4_content_leaks`` -- pairs whose content is a v4 evaluation pair;
* ``internal_content_duplicates`` -- pairs admitted twice under different keys.

Measured on the published sets at the time of writing: 32 leaks (seed 7) and 36
(seed 123), plus 29/32 internal duplicates. The rebuilt sets report zero for both.
See ``reports/decontamination_verification.json``.

    python scripts/audit_training_pool_contamination.py
    python scripts/audit_training_pool_contamination.py --training-set tag=path.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vrf.io_utils import read_jsonl, write_json
from vrf.relational_benchmark import pair_content_fingerprint

DEFAULT_POOLS = [
    "data/processed/secure_code_primevul_pair_diff_time_train_le2020_balanced_6000_metadata.jsonl",
    "data/processed/secure_code_patcheval_pair_diff_all_metadata.jsonl",
    "data/processed/secure_code_deltasecommits_pair_diff_cpp_all_metadata_v2.jsonl",
    "data/processed/secure_code_crossvul_pair_diff_eval_metadata.jsonl",
    "data/processed/secure_code_crossvul_pair_diff_multilang_eval_metadata.jsonl",
    "data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_metadata.jsonl",
    "data/processed/secure_code_primevul_pair_diff_time_eval_ge2021_balanced_2000_metadata.jsonl",
    "data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl",
    "data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata_v2.jsonl",
]

DEFAULT_TRAINING_SETS = [
    "v1_seed7_published=data/processed/secure_code_polarity_balanced_train_scaled_v1.jsonl",
    "v1_seed123_published=data/processed/secure_code_polarity_balanced_train_scaled_seed123.jsonl",
    "v2_seed7_decontaminated=data/processed/secure_code_polarity_balanced_train_decontaminated_v2.jsonl",
    "v2_seed123_decontaminated=data/processed/secure_code_polarity_balanced_train_decontaminated_v2_seed123.jsonl",
    "v3_seed7_mined=data/processed/secure_code_polarity_balanced_train_mined_v3.jsonl",
    "v3_seed123_mined=data/processed/secure_code_polarity_balanced_train_mined_v3_seed123.jsonl",
]


def load_pool(pools: list[str]) -> dict[str, list[dict[str, Any]]]:
    rows_by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rel in pools:
        path = ROOT / rel
        if not path.exists():
            continue
        for row in read_jsonl(path):
            rows_by_key[str(row.get("pair_key") or row["id"])].append(row)
    return rows_by_key


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pool", action="append", help="repeatable path to a pair-diff metadata file")
    parser.add_argument("--training-set", action="append", help="repeatable, tag=path")
    parser.add_argument("--suite", default="data/processed/secure_code_relational_benchmark_v4.jsonl")
    parser.add_argument("--output", default="reports/decontamination_verification.json")
    args = parser.parse_args()

    rows_by_key = load_pool(args.pool or DEFAULT_POOLS)
    print(f"pool: {len(rows_by_key)} distinct pair_keys")

    suite_keys = {str(r["pair_key"]) for r in read_jsonl(ROOT / args.suite)}
    suite_fingerprints: set[str] = set()
    unresolved_suite = 0
    for key in suite_keys:
        rows = rows_by_key.get(key)
        if rows and len(rows) >= 2:
            suite_fingerprints.add(pair_content_fingerprint(rows[:2]))
        else:
            unresolved_suite += 1
    # Fewer fingerprints than pairs does not mean pairs were lost: the suite itself
    # contains content twins (1,245 pairs -> 1,237 distinct fingerprints on v4).
    print(f"suite: {len(suite_keys)} pairs, {len(suite_fingerprints)} distinct content "
          f"fingerprints, {unresolved_suite} unresolved")
    if unresolved_suite:
        print("  WARNING: unresolved suite pairs are NOT covered by this audit.")
    print()

    results: dict[str, Any] = {}
    exit_code = 0
    for spec in args.training_set or DEFAULT_TRAINING_SETS:
        tag, rel = spec.split("=", 1)
        path = ROOT / rel
        if not path.exists():
            print(f"{tag:28s} MISSING {rel}")
            continue
        keys = {str(r.get("pair_key") or r.get("id")).split("::")[-1] for r in read_jsonl(path)}
        fingerprints: dict[str, str] = {}
        unresolved = 0
        for key in keys:
            rows = rows_by_key.get(key)
            if rows and len(rows) >= 2:
                fingerprints[key] = pair_content_fingerprint(rows[:2])
            else:
                unresolved += 1
        leaks = sorted(k for k, fp in fingerprints.items() if fp in suite_fingerprints)
        duplicates = len(fingerprints) - len(set(fingerprints.values()))
        clean = not leaks and not duplicates
        if not clean:
            exit_code = 1
        results[tag] = {
            "path": rel,
            "pairs": len(keys),
            "unresolved": unresolved,
            "suite_content_leaks": len(leaks),
            "internal_content_duplicates": duplicates,
            "leak_examples": leaks[:10],
            "clean": clean,
        }
        print(f"{tag:28s} pairs={len(keys):5d} suite-content-leaks={len(leaks):4d} "
              f"internal-dupes={duplicates:4d} unresolved={unresolved:4d} "
              f"{'CLEAN' if clean else 'CONTAMINATED'}")

    write_json(ROOT / args.output, {"suite": args.suite, "training_sets": results})
    print(f"\nwrote {args.output}")
    print("exit 1 signals at least one contaminated set." if exit_code else "\nall audited sets clean.")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

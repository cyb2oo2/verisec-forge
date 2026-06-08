from __future__ import annotations

import argparse
import json
import sys
from difflib import SequenceMatcher
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_json
from vrf.joint_reasoning import build_side_choice_text, reverse_side_choice_text


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    index = min(int(fraction * len(values)), len(values) - 1)
    return values[index]


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare synthetic reversed diffs with real reverse-direction pairs.")
    parser.add_argument(
        "--dataset",
        default="data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl",
    )
    parser.add_argument(
        "--output",
        default="reports/secure_code_primevul_synthetic_reverse_fidelity_v1.json",
    )
    args = parser.parse_args()

    grouped: dict[str, list[dict]] = {}
    for row in read_jsonl(ROOT / args.dataset):
        grouped.setdefault(str(row.get("pair_key") or row["id"]), []).append(row)
    similarities = []
    exact = 0
    for rows in grouped.values():
        if len(rows) != 2 or {bool(row.get("has_vulnerability")) for row in rows} != {False, True}:
            continue
        first, second = rows
        synthetic = reverse_side_choice_text(build_side_choice_text(first))
        real = build_side_choice_text(second)
        exact += synthetic == real
        similarities.append(SequenceMatcher(None, synthetic, real, autojunk=False).ratio())
    similarities.sort()
    report = {
        "status": "ok",
        "scope": "synthetic_reverse_vs_real_reverse",
        "pairs": len(similarities),
        "exact_matches": exact,
        "exact_match_rate": exact / len(similarities) if similarities else 0.0,
        "mean_character_similarity": sum(similarities) / len(similarities) if similarities else 0.0,
        "character_similarity_percentiles": {
            "p10": percentile(similarities, 0.10),
            "p50": percentile(similarities, 0.50),
            "p90": percentile(similarities, 0.90),
        },
        "interpretation": (
            "Synthetic reversal is a high-similarity augmentation but not an exact substitute for real bidirectional "
            "pairs. Treat it as a consistency view rather than equivalent gold supervision."
        ),
    }
    write_json(ROOT / args.output, report)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

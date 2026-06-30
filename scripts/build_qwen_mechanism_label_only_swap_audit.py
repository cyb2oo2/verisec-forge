from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_json, write_jsonl
from vrf.qwen_mechanism_audit import audit_row

_PLACEHOLDER = "\x00SIDE_TOKEN_PLACEHOLDER\x00"


def label_only_swap(text: str) -> str:
    """Swap the literal "Side A" / "Side B" tokens throughout the prompt
    without touching the underlying diff +/- content. The diff body's
    removed/added lines are agnostic to what we call the two files; this is
    a pure relabeling, not a content or structural-position change.

    Verified occurrences in the canonical renderer
    (src/vrf/relational_benchmark.py): the "Unified diff from Side A to Side
    B:" header sentence and the "--- Side A" / "+++ Side B" diff markers.
    No other "Side A"/"Side B" mentions exist in the instruction text.
    """
    swapped = text.replace("Side A", _PLACEHOLDER)
    swapped = swapped.replace("Side B", "Side A")
    swapped = swapped.replace(_PLACEHOLDER, "Side B")
    return swapped


def build_rows(bases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for base in bases:
        flipped_gold = "B" if base["gold_riskier_side"] == "A" else "A"
        rows.append(
            audit_row(
                base,
                variant="label_only_swap",
                family="side_order_label_vs_position",
                text=label_only_swap(base["text"]),
                expected_relation="equivariant_swap",
                gold_side=flipped_gold,
            )
        )
        rows.append(
            audit_row(
                base,
                variant="canonical",
                family="side_order_label_vs_position",
                text=base["text"],
                expected_relation="identity",
            )
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the label-only-swap audit: swap the literal 'Side A'/"
            "'Side B' tokens in the prompt without moving any diff content "
            "or structural position, isolating whether the model's bias "
            "tracks the text label or the structural (first/second) slot."
        ),
    )
    parser.add_argument("--benchmark", default="data/processed/secure_code_relational_benchmark_v2.jsonl")
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_qwen_mechanism_label_only_swap_audit_v1.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_qwen_mechanism_label_only_swap_audit_dataset_v1.json",
    )
    args = parser.parse_args()

    benchmark = read_jsonl(ROOT / args.benchmark)
    bases = [
        row
        for row in benchmark
        if row["sampling_suite"] == "representative" and row["expected_relation"] == "identity"
    ]
    rows = build_rows(bases)

    write_jsonl(ROOT / args.output, rows)
    summary = {
        "status": "ok",
        "scope": "qwen_mechanism_label_only_swap_audit",
        "base_pairs": len(bases),
        "rows": len(rows),
        "variants": sorted({row["audit_variant"] for row in rows}),
    }
    write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

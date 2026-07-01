from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (SRC, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from vrf.io_utils import read_jsonl, write_json, write_jsonl
from vrf.qwen_mechanism_audit import audit_row
from scripts.build_qwen_mechanism_label_only_swap_audit import label_only_swap


def polarity_only_swap(swap_text: str) -> str:
    """Flip the diff hunk polarity while holding the Side A/Side B labels and
    the gold answer fixed -- the complement of ``label_only_swap``.

    ``label_only_swap`` moved the "Side A"/"Side B" words and held the diff
    body fixed. This transform does the mirror image: it holds the label
    meaning fixed (Side A keeps denoting the same underlying code, gold is
    unchanged) and flips which content is on the removed (``-``) vs added
    (``+``) lines.

    Construction: start from the already-reverse-rendered ``canonical_
    renderer_swap_v2`` text. ``swap_pair()`` exchanged ``side_a``/``side_b``
    and regenerated the whole diff via ``difflib``, so that text already has
    the flipped polarity (canonical ``-side_a``/``+side_b`` becomes
    ``-side_b``/``+side_a``) -- but it *also* moved the label->content binding
    (its "Side A" now denotes the canonical ``side_b``, and its gold is
    flipped). Applying ``label_only_swap`` -- a pure "Side A"<->"Side B" word
    substitution -- relabels the words back so "Side A" again denotes the
    canonical ``side_a`` content, restoring the label meaning and the gold
    answer while leaving the flipped ``-``/``+`` body byte-for-byte intact.

    Net effect vs. canonical: the only thing that changes is diff hunk
    polarity / structural content order (which content is removed vs added,
    and the from->to direction). The words "Side A"/"Side B" denote the same
    code they did canonically and ``gold_riskier_side`` is unchanged, so any
    prediction change is attributable to the polarity flip alone.
    """
    return label_only_swap(swap_text)


def build_rows(
    bases: list[dict[str, Any]],
    swaps: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for base in bases:
        swap = swaps[base["id"]]
        rows.append(
            audit_row(
                base,
                variant="polarity_only_swap",
                family="side_order_polarity_vs_label",
                text=polarity_only_swap(swap["text"]),
                # gold is UNCHANGED from canonical: the relabeling restores
                # "Side A" to the canonical side_a content, so the riskier
                # side keeps the same letter. A robust, content-tracking model
                # should therefore give the same answer as canonical
                # (invariant); a polarity-driven one flips with the body.
                expected_relation="invariant",
                gold_side=base["gold_riskier_side"],
            )
        )
        # The plain side_swap row (labels + polarity both moved, gold flipped)
        # re-derived on the same 600-pair base set, so canonical vs
        # polarity_only_swap vs side_swap can all be compared on identical
        # underlying pairs in one report. Its diff body is byte-identical to
        # polarity_only_swap -- they differ only in the "Side A"/"Side B"
        # words -- which lets the report show the words are inert directly.
        rows.append(
            audit_row(
                base,
                variant="side_swap",
                family="side_order_polarity_vs_label",
                text=swap["text"],
                expected_relation="equivariant_swap",
                gold_side=swap["gold_riskier_side"],
            )
        )
        rows.append(
            audit_row(
                base,
                variant="canonical",
                family="side_order_polarity_vs_label",
                text=base["text"],
                expected_relation="identity",
            )
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the polarity-only-swap audit: flip the diff hunk polarity "
            "(which content is removed vs added) while holding the 'Side A'/"
            "'Side B' label meaning and the gold answer fixed -- the "
            "complement of the label-only swap. Isolates whether the model's "
            "side bias tracks diff hunk polarity / structural content order or "
            "the prose text labels."
        ),
    )
    parser.add_argument(
        "--benchmark",
        default="data/processed/secure_code_relational_benchmark_v2.jsonl",
    )
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_qwen_mechanism_polarity_only_swap_audit_v1.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_qwen_mechanism_polarity_only_swap_audit_dataset_v1.json",
    )
    args = parser.parse_args()

    benchmark = read_jsonl(ROOT / args.benchmark)
    bases = [
        row
        for row in benchmark
        if row["sampling_suite"] == "representative"
        and row["expected_relation"] == "identity"
    ]
    swaps = {
        row["base_id"]: row
        for row in benchmark
        if row["sampling_suite"] == "representative"
        and row["transformation_template"] == "canonical_renderer_swap_v2"
    }

    rows = build_rows(bases, swaps)

    write_jsonl(ROOT / args.output, rows)
    summary = {
        "status": "ok",
        "scope": "qwen_mechanism_polarity_only_swap_audit",
        "base_pairs": len(bases),
        "rows": len(rows),
        "variants": sorted({row["audit_variant"] for row in rows}),
        "datasets": sorted({row["dataset"] for row in bases}),
    }
    write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

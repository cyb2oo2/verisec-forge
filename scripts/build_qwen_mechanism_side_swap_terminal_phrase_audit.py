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
from vrf.qwen_mechanism_audit import audit_row, padding_variants


def build_interaction_rows(
    bases: list[dict[str, Any]],
    swaps: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for base in bases:
        swap = swaps[base["id"]]
        # Reuse the existing padding_variants() helper, applied to the already
        # side-swapped text instead of the canonical text -- this is the only
        # change needed to cross the two interventions.
        terminal_phrase_text = padding_variants(swap["text"])["padding_post_diff_terminal_phrase"]
        rows.append(
            audit_row(
                base,
                variant="side_swap_padding_post_diff_terminal_phrase",
                family="side_order_endpoint_interaction",
                text=terminal_phrase_text,
                expected_relation="equivariant_swap",
                gold_side=swap["gold_riskier_side"],
            )
        )
        # Also re-derive the plain side_swap row (no padding) and the plain
        # terminal-phrase row (no swap) from the same 600-pair base set, so
        # all three points of the 2x2 (swap x terminal-phrase) grid can be
        # compared on identical underlying pairs in one report.
        rows.append(
            audit_row(
                base,
                variant="side_swap",
                family="side_order_endpoint_interaction",
                text=swap["text"],
                expected_relation="equivariant_swap",
                gold_side=swap["gold_riskier_side"],
            )
        )
        rows.append(
            audit_row(
                base,
                variant="padding_post_diff_terminal_phrase",
                family="side_order_endpoint_interaction",
                text=padding_variants(base["text"])["padding_post_diff_terminal_phrase"],
            )
        )
        rows.append(
            audit_row(
                base,
                variant="canonical",
                family="side_order_endpoint_interaction",
                text=base["text"],
                expected_relation="identity",
            )
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the side-swap x terminal-phrase interaction audit: the "
            "padding_post_diff_terminal_phrase transform applied to already-"
            "side-swapped text, isolating whether the endpoint-collapse fix "
            "also repairs side-swap equivariance, or whether they are "
            "independent failure modes."
        ),
    )
    parser.add_argument("--benchmark", default="data/processed/secure_code_relational_benchmark_v2.jsonl")
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_qwen_mechanism_side_swap_terminal_phrase_audit_v1.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_qwen_mechanism_side_swap_terminal_phrase_audit_dataset_v1.json",
    )
    args = parser.parse_args()

    benchmark = read_jsonl(ROOT / args.benchmark)
    bases = [
        row
        for row in benchmark
        if row["sampling_suite"] == "representative" and row["expected_relation"] == "identity"
    ]
    swaps = {
        row["base_id"]: row
        for row in benchmark
        if row["sampling_suite"] == "representative"
        and row["transformation_template"] == "canonical_renderer_swap_v2"
    }

    rows = build_interaction_rows(bases, swaps)

    write_jsonl(ROOT / args.output, rows)
    summary = {
        "status": "ok",
        "scope": "qwen_mechanism_side_swap_terminal_phrase_audit",
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

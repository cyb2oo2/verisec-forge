from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_json, write_jsonl
from vrf.qwen_mechanism_audit import (
    audit_row,
    clang_format_code,
    expand_c_like_separators,
    padding_variants,
    replace_pair_code,
    training_prompt,
    transform_pair_code,
)
from vrf.relational_benchmark import (
    build_canonical_pair,
    render_pair,
    swap_pair,
)


def load_delta_pairs(path: Path):
    grouped = {}
    for row in read_jsonl(path):
        grouped.setdefault(str(row["pair_key"]), []).append(row)
    return {
        key: build_canonical_pair(key, rows, dataset="deltasecommits")
        for key, rows in grouped.items()
        if len(rows) == 2
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the fixed-pair Qwen relational mechanism audit."
    )
    parser.add_argument(
        "--benchmark",
        default="data/processed/secure_code_relational_benchmark_v2.jsonl",
    )
    parser.add_argument(
        "--delta-source",
        default="data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata.jsonl",
    )
    parser.add_argument(
        "--clang-format",
        default=".venv/Scripts/clang-format.exe",
    )
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_qwen_mechanism_audit_v1.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_qwen_mechanism_audit_dataset_v1.json",
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
    delta_pairs = load_delta_pairs(ROOT / args.delta_source)
    formatter = ROOT / args.clang_format
    rows = []
    for base in bases:
        canonical = audit_row(
            base,
            variant="canonical",
            family="baseline",
            text=base["text"],
            expected_relation="identity",
        )
        rows.append(canonical)
        swap = swaps[base["id"]]
        rows.append(
            audit_row(
                base,
                variant="side_swap",
                family="side_order",
                text=swap["text"],
                expected_relation="equivariant_swap",
                gold_side=swap["gold_riskier_side"],
            )
        )
        for variant, text in padding_variants(base["text"]).items():
            rows.append(
                audit_row(
                    base,
                    variant=variant,
                    family="padding_position",
                    text=text,
                )
            )
        no_metadata = next(
            row
            for row in benchmark
            if row["base_id"] == base["id"]
            and row["transformation_template"] == "metadata_removed_v2"
        )
        rows.append(
            audit_row(
                base,
                variant="canonical_no_metadata",
                family="prompt_contract",
                text=no_metadata["text"],
            )
        )
        if base["dataset"] == "deltasecommits":
            pair = delta_pairs[base["pair_key"]]
        else:
            # The canonical text is already the exact pair representation needed
            # for the training-contract prompt comparison.
            pair = None
        if pair is not None:
            training_text = training_prompt(pair)
            training_swap_text = training_prompt(swap_pair(pair))
            rows.append(
                audit_row(
                    base,
                    variant="training_prompt",
                    family="prompt_contract",
                    text=training_text,
                )
            )
            rows.append(
                audit_row(
                    base,
                    variant="training_prompt_side_swap",
                    family="prompt_contract",
                    text=training_swap_text,
                    expected_relation="equivariant_swap",
                    gold_side=(
                        "B" if base["gold_riskier_side"] == "A" else "A"
                    ),
                )
            )
            for variant, transform in (
                ("delta_raw", lambda value: value),
                ("delta_separator_expanded", expand_c_like_separators),
            ):
                transformed = transform_pair_code(pair, transform)
                rows.append(
                    audit_row(
                        base,
                        variant=variant,
                        family="delta_representation",
                        text=render_pair(transformed),
                    )
                )
                if variant == "delta_raw":
                    continue
                transformed_text = render_pair(transformed)
                rows.append(
                    audit_row(
                        base,
                        variant=f"{variant}_side_swap",
                        family="delta_representation",
                        text=render_pair(swap_pair(transformed)),
                        expected_relation="equivariant_swap",
                        gold_side=(
                            "B" if base["gold_riskier_side"] == "A" else "A"
                        ),
                    )
                )
                rows.append(
                    audit_row(
                        base,
                        variant=f"{variant}_post_diff",
                        family="delta_representation",
                        text=padding_variants(transformed_text)[
                            "padding_post_diff"
                        ],
                    )
                )
            formatted_a = clang_format_code(
                pair.side_a.code, executable=formatter
            )
            formatted_b = clang_format_code(
                pair.side_b.code, executable=formatter
            )
            transformed = replace_pair_code(
                pair,
                side_a_code=formatted_a.code,
                side_b_code=formatted_b.code,
            )
            format_metadata = {
                "normalization_contract": (
                    "clang-format when successful; regex separator fallback "
                    "otherwise; not validated semantics-preserving"
                ),
                "side_a_clang_format_success": formatted_a.success,
                "side_a_fallback_used": formatted_a.fallback_used,
                "side_b_clang_format_success": formatted_b.success,
                "side_b_fallback_used": formatted_b.fallback_used,
                "both_sides_clang_format_success": (
                    formatted_a.success and formatted_b.success
                ),
            }
            transformed_text = render_pair(transformed)
            rows.append(
                audit_row(
                    base,
                    variant="delta_clang_format",
                    family="delta_representation",
                    text=transformed_text,
                    audit_metadata=format_metadata,
                )
            )
            rows.append(
                audit_row(
                    base,
                    variant="delta_clang_format_side_swap",
                    family="delta_representation",
                    text=render_pair(swap_pair(transformed)),
                    expected_relation="equivariant_swap",
                    gold_side=(
                        "B" if base["gold_riskier_side"] == "A" else "A"
                    ),
                    audit_metadata=format_metadata,
                )
            )
            rows.append(
                audit_row(
                    base,
                    variant="delta_clang_format_post_diff",
                    family="delta_representation",
                    text=padding_variants(transformed_text)[
                        "padding_post_diff"
                    ],
                    audit_metadata=format_metadata,
                )
            )
        else:
            # Reconstruct the training-style instruction while retaining the
            # canonical diff body for non-Delta sources.
            diff = base["text"].split(
                "Unified diff from Side A to Side B:\n", 1
            )[1]
            training_text = (
                "Task: compare two versions of the same code change.\n"
                "The unified diff transforms Side A into Side B.\n"
                "Predict which side contains the security vulnerability.\n\n"
                f"{diff}"
            )
            swap_diff = swap["text"].split(
                "Unified diff from Side A to Side B:\n", 1
            )[1]
            training_swap_text = (
                "Task: compare two versions of the same code change.\n"
                "The unified diff transforms Side A into Side B.\n"
                "Predict which side contains the security vulnerability.\n\n"
                f"{swap_diff}"
            )
            rows.append(
                audit_row(
                    base,
                    variant="training_prompt",
                    family="prompt_contract",
                    text=training_text,
                )
            )
            rows.append(
                audit_row(
                    base,
                    variant="training_prompt_side_swap",
                    family="prompt_contract",
                    text=training_swap_text,
                    expected_relation="equivariant_swap",
                    gold_side=(
                        "B" if base["gold_riskier_side"] == "A" else "A"
                    ),
                )
            )

    write_jsonl(ROOT / args.output, rows)
    summary = {
        "status": "ok",
        "pairs": len(bases),
        "rows": len(rows),
        "datasets": {
            dataset: sum(row["dataset"] == dataset for row in bases)
            for dataset in sorted({row["dataset"] for row in bases})
        },
        "families": {
            family: sum(row["audit_family"] == family for row in rows)
            for family in sorted({row["audit_family"] for row in rows})
        },
        "variants": {
            variant: sum(row["audit_variant"] == variant for row in rows)
            for variant in sorted({row["audit_variant"] for row in rows})
        },
        "clang_format": str(formatter),
        "clang_format_status": {
            "both_sides_success_pairs": sum(
                row.get("audit_metadata", {}).get(
                    "both_sides_clang_format_success", False
                )
                for row in rows
                if row["audit_variant"] == "delta_clang_format"
            ),
            "fallback_pairs": sum(
                not row.get("audit_metadata", {}).get(
                    "both_sides_clang_format_success", False
                )
                for row in rows
                if row["audit_variant"] == "delta_clang_format"
            ),
            "parse_validation_available": False,
        },
    }
    write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

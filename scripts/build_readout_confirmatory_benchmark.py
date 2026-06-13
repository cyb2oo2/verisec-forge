from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_json, write_jsonl
from vrf.relational_benchmark import (
    build_canonical_pair,
    pair_metadata,
    render_pair,
    sample_representative,
    structural_accounting,
    swap_pair,
)


DEFAULT_SOURCES = {
    "primevul": (
        "data/processed/"
        "secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl"
    ),
    "deltasecommits": (
        "data/processed/"
        "secure_code_deltasecommits_pair_diff_cpp_eval_metadata.jsonl"
    ),
    "patcheval": (
        "data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl"
    ),
}

SUFFIX_SPECS = {
    "confirm_suffix_short_v1": (
        8,
        lambda index: f"// audit-neutral-note-{index + 1}: unchanged",
    ),
    "confirm_suffix_medium_v1": (
        32,
        lambda index: f"/* review-context-{index + 1}: informational only */",
    ),
    "confirm_suffix_long_v1": (
        96,
        lambda index: f"// documentation-record[{index + 1}]=no-semantic-change",
    ),
}


def load_pairs(dataset: str, path: Path):
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in read_jsonl(path):
        grouped.setdefault(str(row.get("pair_key") or row["id"]), []).append(
            row
        )
    pairs = []
    for pair_key, rows in grouped.items():
        try:
            pairs.append(
                build_canonical_pair(pair_key, rows, dataset=dataset)
            )
        except ValueError:
            continue
    return pairs


def discovery_keys(path: Path) -> set[tuple[str, str]]:
    return {
        (str(row["dataset"]), str(row["pair_key"]))
        for row in read_jsonl(path)
        if row["audit_variant"] == "canonical"
    }


def suffix_text(base_text: str, spec) -> str:
    lines, renderer = spec
    return (
        f"{base_text.rstrip()}\n\n"
        "Independent neutral review context:\n"
        + "\n".join(renderer(index) for index in range(lines))
        + "\n"
    )


def benchmark_row(
    pair,
    *,
    variant: str,
    text: str,
    expected_relation: str,
    gold_side: str | None = None,
    transformation_char_spans: list[dict[str, int]] | None = None,
) -> dict[str, Any]:
    metadata = pair_metadata(pair)
    base_id = f"confirm::{pair.dataset}::{pair.pair_key}::canonical"
    return {
        "id": f"confirm::{pair.dataset}::{pair.pair_key}::{variant}",
        "base_id": base_id,
        **metadata,
        "sampling_suite": "independent_confirmatory",
        "audit_family": (
            "baseline"
            if variant == "canonical"
            else "side_order"
            if variant == "side_swap"
            else "unseen_suffix"
        ),
        "audit_variant": variant,
        "transformation_family": (
            "base"
            if variant == "canonical"
            else "side_order"
            if variant == "side_swap"
            else "padding"
        ),
        "transformation_template": variant,
        "expected_relation": expected_relation,
        "gold_riskier_side": gold_side or metadata["gold_riskier_side"],
        "validation_tier": 1,
        "validation": {
            "structural_valid": True,
            "semantic_basis": (
                "independent vulnerable/fixed pair"
                if variant == "canonical"
                else "same pair with A/B order reversed"
                if variant == "side_swap"
                else "unseen neutral comment suffix appended after complete diff"
            ),
        },
        "changed_regions": (
            []
            if variant == "canonical"
            else ["side_order", "diff_direction"]
            if variant == "side_swap"
            else ["prompt_suffix"]
        ),
        "runtime_transform": {
            "transformation_char_spans": transformation_char_spans or []
        },
        "text": text,
        "structural_accounting": structural_accounting(text),
        "benchmark_version": "VeriPatch-RR-readout-confirm-v1",
        "selection_seed": 20260613,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the independent readout confirmatory benchmark."
    )
    parser.add_argument("--pairs-per-source", type=int, default=60)
    parser.add_argument("--seed", type=int, default=20260613)
    parser.add_argument(
        "--discovery-audit",
        default="data/processed/secure_code_qwen_mechanism_audit_v1.jsonl",
    )
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_readout_confirmatory_v1.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_readout_confirmatory_dataset_v1.json",
    )
    args = parser.parse_args()

    excluded = discovery_keys(ROOT / args.discovery_audit)
    selected = []
    eligibility = {}
    for dataset, relpath in DEFAULT_SOURCES.items():
        pairs = load_pairs(dataset, ROOT / relpath)
        remaining = [
            pair
            for pair in pairs
            if (dataset, str(pair.pair_key)) not in excluded
        ]
        if len(remaining) < args.pairs_per_source:
            raise ValueError(
                f"{dataset} has only {len(remaining)} unseen pairs"
            )
        sample = sample_representative(
            remaining,
            limit=args.pairs_per_source,
            seed=args.seed,
        )
        selected.extend(sample)
        eligibility[dataset] = {
            "eligible_total": len(pairs),
            "discovery_excluded": len(pairs) - len(remaining),
            "remaining_unseen": len(remaining),
            "selected": len(sample),
        }

    rows = []
    for pair in selected:
        canonical_text = render_pair(pair)
        rows.append(
            benchmark_row(
                pair,
                variant="canonical",
                text=canonical_text,
                expected_relation="identity",
            )
        )
        swapped = swap_pair(pair)
        rows.append(
            benchmark_row(
                pair,
                variant="side_swap",
                text=render_pair(swapped),
                expected_relation="equivariant_swap",
                gold_side=swapped.gold_riskier_side,
            )
        )
        for variant, spec in SUFFIX_SPECS.items():
            transformed = suffix_text(canonical_text, spec)
            suffix_start = len(canonical_text.rstrip())
            rows.append(
                benchmark_row(
                    pair,
                    variant=variant,
                    text=transformed,
                    expected_relation="invariant",
                    transformation_char_spans=[
                        {
                            "char_start": suffix_start,
                            "char_end": len(transformed),
                        }
                    ],
                )
            )
    write_jsonl(ROOT / args.output, rows)
    selected_keys = {
        (str(row["dataset"]), str(row["pair_key"])) for row in rows
    }
    overlap = selected_keys & excluded
    summary = {
        "status": "ok" if not overlap else "failed",
        "benchmark": "VeriPatch-RR-readout-confirm-v1",
        "selection_seed": args.seed,
        "pairs": len(selected_keys),
        "rows": len(rows),
        "datasets": dict(
            Counter(row["dataset"] for row in rows if row["audit_variant"] == "canonical")
        ),
        "variants": dict(Counter(row["audit_variant"] for row in rows)),
        "discovery_pair_overlap": len(overlap),
        "eligibility": eligibility,
        "claim_boundary": (
            "Pair IDs and suffix templates are independent of the PR #8 "
            "discovery instrument."
        ),
    }
    write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2))
    return 0 if not overlap else 1


if __name__ == "__main__":
    raise SystemExit(main())

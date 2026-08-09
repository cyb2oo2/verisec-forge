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
    build_interventions,
    pair_metadata,
    render_pair,
    sample_balanced_stress,
    sample_representative,
    sampling_diagnostics,
    structural_accounting,
    swap_mirror_is_exact,
)


DEFAULT_SOURCES = [
    "primevul=data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl",
    # v2: newline-normalised `code` field. The pre-v2 file stores every function
    # on one line, which the exact-mirror invariant rejects wholesale (327/327).
    "deltasecommits=data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata_v2.jsonl",
    "patcheval=data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl",
]


def parse_source(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise ValueError("source must use name=path")
    name, path = value.split("=", 1)
    return name.strip(), ROOT / path.strip()


def load_pairs(name: str, path: Path):
    """Load canonical pairs, rejecting any that cannot support a side swap.

    Construction-time invariant: a pair is admitted only when swapping its sides
    produces an exact structural mirror of the rendering. Pairs that fail carry
    no line-level polarity structure, so every side-swap metric computed over
    them is meaningless. The rejection rate is published in the summary rather
    than being silently absorbed.
    """

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in read_jsonl(path):
        grouped.setdefault(str(row.get("pair_key") or row["id"]), []).append(row)
    pairs = []
    skipped = 0
    rejected_non_mirror = 0
    for pair_key, rows in grouped.items():
        try:
            pair = build_canonical_pair(pair_key, rows, dataset=name)
        except ValueError:
            skipped += 1
            continue
        if not swap_mirror_is_exact(pair):
            rejected_non_mirror += 1
            continue
        pairs.append(pair)

    # Fail loudly rather than emitting a benchmark that silently omits a source.
    # A source that renders no valid side swap at all is a data defect, not an
    # empty sample: this is exactly how the DeltaSecommits newline defect went
    # unnoticed while contaminating every side-swap number built over it.
    if not pairs and rejected_non_mirror:
        raise SystemExit(
            f"source {name!r} ({path}): every one of {rejected_non_mirror} pairs "
            "fails the exact-mirror invariant, so it can support no side-swap "
            "measurement. This usually means the source stores each function on "
            "a single line. Fix ingestion (see normalize_code_for_diff) rather "
            "than proceeding with the source silently dropped."
        )
    return pairs, skipped, rejected_non_mirror


def build_rows(pairs, *, seed: int, suite: str) -> list[dict[str, Any]]:
    rows = []
    for pair in pairs:
        metadata = pair_metadata(pair)
        base_id = f"{suite}::{pair.dataset}::{pair.pair_key}::base"
        base_text = render_pair(pair)
        rows.append(
            {
                "id": base_id,
                "base_id": base_id,
                **metadata,
                "sampling_suite": suite,
                "transformation_family": "base",
                "transformation_template": "canonical_pair_renderer_v2",
                "expected_relation": "identity",
                "validation_tier": 1,
                "validation": {
                    "structural_valid": True,
                    "semantic_basis": "canonical vulnerable/fixed pair",
                },
                "changed_regions": [],
                "runtime_transform": {},
                "text": base_text,
                "structural_accounting": structural_accounting(base_text),
                "benchmark_version": "VeriPatch-RR-v0.1",
                "seed": seed,
            }
        )
        for intervention in build_interventions(pair):
            transformed_gold = metadata["gold_riskier_side"]
            if intervention.expected_relation == "equivariant_swap":
                transformed_gold = "B" if transformed_gold == "A" else "A"
            rows.append(
                {
                    "id": f"{base_id}::{intervention.template}",
                    "base_id": base_id,
                    **metadata,
                    "base_gold_riskier_side": metadata["gold_riskier_side"],
                    "gold_riskier_side": transformed_gold,
                    "sampling_suite": suite,
                    "transformation_family": intervention.family,
                    "transformation_template": intervention.template,
                    "expected_relation": intervention.expected_relation,
                    "validation_tier": intervention.validation_tier,
                    "validation": intervention.validation,
                    "changed_regions": intervention.changed_regions,
                    "runtime_transform": intervention.runtime_transform,
                    "text": intervention.text,
                    "structural_accounting": intervention.structural_accounting,
                    "benchmark_version": "VeriPatch-RR-v0.1",
                    "seed": seed,
                }
            )
    return rows


def summarize(
    rows: list[dict[str, Any]], source_summaries: dict[str, Any], args
) -> dict[str, Any]:
    base_rows = [
        row for row in rows if row["transformation_family"] == "base"
    ]
    intervention_rows = [
        row for row in rows if row["transformation_family"] != "base"
    ]
    suite_summaries = {}
    for suite in sorted({row["sampling_suite"] for row in base_rows}):
        suite_rows = [row for row in base_rows if row["sampling_suite"] == suite]
        suite_summaries[suite] = {
            "pairs": len(suite_rows),
            "datasets": dict(Counter(row["dataset"] for row in suite_rows)),
            "diff_buckets": dict(
                Counter(row["diff_bucket"] for row in suite_rows)
            ),
            "character_buckets": dict(
                Counter(row["character_bucket"] for row in suite_rows)
            ),
            "maximum_project_concentration": max(
                Counter(
                    (row["dataset"], row["project"]) for row in suite_rows
                ).values(),
                default=0,
            )
            / max(1, len(suite_rows)),
        }
    return {
        "status": "ok",
        "benchmark": "VeriPatch-RR-v0.1",
        "pairs": len(base_rows),
        "unique_source_pairs": len(
            {(row["dataset"], row["pair_key"]) for row in base_rows}
        ),
        "rows": len(rows),
        "intervention_rows": len(intervention_rows),
        "sampling": {
            "seed": args.seed,
            "pairs_per_source_per_suite": args.pairs_per_source,
            "suites": ["representative", "balanced_stress"],
            "balance_dimensions": ["diff_bucket", "character_bucket"],
            "caps": ["project", "cwe"],
        },
        "tokenizer_neutral": True,
        "runtime_accounting_required": True,
        "source_summaries": source_summaries,
        "suite_summaries": suite_summaries,
        "transformation_templates": dict(
            Counter(
                row["transformation_template"] for row in intervention_rows
            )
        ),
        "validation_tiers": dict(
            Counter(str(row["validation_tier"]) for row in intervention_rows)
        ),
        "claim_boundary": (
            "VeriPatch-RR v0.1 stores tokenizer-neutral text, structural spans, "
            "and transformation contracts. Token visibility, exact context-pressure "
            "ratios, and truncation subsets must be materialized per model runtime."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build tokenizer-neutral VeriPatch-RR v0.1."
    )
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--pairs-per-source", type=int, default=200)
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_relational_benchmark_v2.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_relational_benchmark_v2_summary.json",
    )
    args = parser.parse_args()

    all_rows = []
    source_summaries = {}
    for source_value in args.source or DEFAULT_SOURCES:
        name, path = parse_source(source_value)
        pairs, skipped, rejected_non_mirror = load_pairs(name, path)
        representative = sample_representative(
            pairs, limit=args.pairs_per_source, seed=args.seed
        )
        balanced = sample_balanced_stress(
            pairs, limit=args.pairs_per_source, seed=args.seed
        )
        all_rows.extend(
            build_rows(representative, seed=args.seed, suite="representative")
        )
        all_rows.extend(
            build_rows(balanced, seed=args.seed, suite="balanced_stress")
        )
        source_summaries[name] = {
            "input": str(path.relative_to(ROOT)).replace("\\", "/"),
            "eligible_pairs": len(pairs),
            "skipped_groups": skipped,
            "rejected_non_mirror_pairs": rejected_non_mirror,
            "non_mirror_rejection_rate": (
                rejected_non_mirror / (len(pairs) + rejected_non_mirror)
                if (len(pairs) + rejected_non_mirror)
                else 0.0
            ),
            "representative": sampling_diagnostics(
                representative, suite="representative"
            ),
            "balanced_stress": sampling_diagnostics(
                balanced,
                suite="balanced_stress",
                target_diff_buckets=[
                    "00-02",
                    "03-05",
                    "06-10",
                    "11-25",
                    "26+",
                ],
                target_character_buckets=[
                    "<=1k",
                    "1k-4k",
                    "4k-16k",
                    "16k+",
                ],
            ),
        }
    write_jsonl(ROOT / args.output, all_rows)
    summary = summarize(all_rows, source_summaries, args)
    write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

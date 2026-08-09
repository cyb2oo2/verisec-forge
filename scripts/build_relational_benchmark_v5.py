"""Build the v5 wide-context relational suite.

v5 changes **exactly one thing** relative to v4: how much unchanged surrounding
code each rendering shows. Same sources, same sampling seed, same pairs, same
polarity-balanced slice, same metadata block, same two rendering families. Only
``difflib``'s context-line budget ``n`` moves, from 3 to ``--context-lines``.

Why this is the right shape for the task-formulation phase
----------------------------------------------------------
The decisive metric is accuracy on pairs where net polarity points the wrong
way. Net polarity is computed from the ``+``/``-`` lines, which widening the
context window does not touch: context lines are emitted with a leading space.
So the control's accuracy, the four ``(gold x net-sign)`` cells, and therefore
the balanced slice are all **identical by construction** to v4. The suite
asserts this rather than trusting it.

That makes v5 a clean single-variable ablation: any movement in discordant
accuracy is attributable to the extra surrounding code and to nothing else.

Why not render the whole function/file
--------------------------------------
Measured on the 1,245 v4 pairs with the Qwen2.5-Coder tokenizer, an unbounded
context budget puts 31.4% of rows over 2,048 tokens (p90 = 13,979). Truncation
is applied per row, and the canonical and side-swap renderings of a pair do not
truncate at the same point, so a truncated pair is **no longer an exact
mirror** -- the invariant would be silently destroyed on a third of the suite.
``n=32`` keeps rows over 2,048 at 3.4%, which is the regime the published v4
suite already operates in at 1,024 (2-5% per source).

Wide-context, not full-unit: at ``n=32`` PrimeVul / PatchEval / DeltaSecommits
units are effectively covered end to end, while CrossVul's median 28k-character
files are shown as a window around each hunk.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vrf.io_utils import read_jsonl, write_json, write_jsonl
from vrf.nuisance_transfer import build_nuisance_rows
from vrf.relational_benchmark import (
    pair_metadata,
    render_pair,
    sample_representative,
    swap_pair,
    swap_mirror_is_exact,
)

from scripts.build_relational_benchmark_v2 import load_pairs, parse_source
from scripts.build_relational_benchmark_v4 import (
    DEFAULT_SOURCES,
    ingestion_defects,
    polarity_balanced_keys,
)


def build_rows(
    pairs: list[Any], *, balanced: set[tuple[str, str]], context_lines: int
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for pair in pairs:
        metadata = pair_metadata(pair)
        in_slice = (pair.dataset, pair.pair_key) in balanced
        gold = "A" if pair.side_a.vulnerable else "B"
        flipped = "B" if gold == "A" else "A"

        glyph_canonical = render_pair(pair, context_lines=context_lines)
        glyph_swap = render_pair(swap_pair(pair), context_lines=context_lines)
        prose_canonical, prose_swap = build_nuisance_rows(
            pair, "split_view", context_lines=context_lines
        )

        base_id = f"v5::{pair.dataset}::{pair.pair_key}::glyph::canonical"
        for family, variant, text, side_gold, relation in (
            ("glyph", "canonical", glyph_canonical, gold, "identity"),
            ("glyph", "side_swap", glyph_swap, flipped, "equivariant"),
            ("prose", "canonical", prose_canonical, gold, "invariant"),
            ("prose", "side_swap", prose_swap, flipped, "equivariant"),
        ):
            rows.append(
                {
                    "id": f"v5::{pair.dataset}::{pair.pair_key}::{family}::{variant}",
                    "base_id": base_id,
                    "pair_key": pair.pair_key,
                    "dataset": pair.dataset,
                    **{
                        k: v
                        for k, v in metadata.items()
                        if k not in ("id", "pair_key", "dataset")
                    },
                    "rendering_family": family,
                    "audit_variant": f"{family}__{variant}"
                    if family == "prose"
                    else variant,
                    "transformation_family": family,
                    "transformation_template": f"v5_{family}_{variant}",
                    "expected_relation": relation,
                    "gold_riskier_side": side_gold,
                    "polarity_balanced_slice": in_slice,
                    "context_lines": context_lines,
                    "runtime_transform": {},
                    "text": text,
                }
            )
    return rows


def assert_parity_with_v4(rows: list[dict[str, Any]], v4_path: Path) -> dict[str, Any]:
    """v5 must differ from v4 in rendering width and nothing else.

    Guards the single-variable claim: if the pair set or the balanced slice
    moved, discordant-accuracy movement would no longer be attributable to
    context width alone.
    """

    v4 = list(read_jsonl(v4_path))
    v4_pairs = {r["pair_key"] for r in v4}
    v5_pairs = {r["pair_key"] for r in rows}
    v4_slice = {r["pair_key"] for r in v4 if r.get("polarity_balanced_slice")}
    v5_slice = {r["pair_key"] for r in rows if r.get("polarity_balanced_slice")}
    v4_gold = {(r["pair_key"], r["audit_variant"]): r["gold_riskier_side"] for r in v4}
    v5_gold = {(r["pair_key"], r["audit_variant"]): r["gold_riskier_side"] for r in rows}
    gold_mismatch = sum(
        1 for k, v in v5_gold.items() if k in v4_gold and v4_gold[k] != v
    )
    problems = []
    if v4_pairs != v5_pairs:
        problems.append(
            f"pair set differs: v4-only={len(v4_pairs - v5_pairs)} v5-only={len(v5_pairs - v4_pairs)}"
        )
    if v4_slice != v5_slice:
        problems.append(
            f"balanced slice differs: v4-only={len(v4_slice - v5_slice)} v5-only={len(v5_slice - v4_slice)}"
        )
    if gold_mismatch:
        problems.append(f"gold differs on {gold_mismatch} rows")
    if problems:
        raise SystemExit(
            "v5 is not a single-variable ablation of v4: " + "; ".join(problems)
        )
    return {
        "pairs": len(v5_pairs),
        "balanced_slice_pairs": len(v5_slice),
        "pair_set_identical": True,
        "balanced_slice_identical": True,
        "gold_identical": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", action="append", default=None)
    parser.add_argument("--pairs-per-source", type=int, default=350)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--context-lines",
        type=int,
        default=32,
        help=(
            "difflib unified-diff context budget. 3 reproduces v4. 32 is the "
            "widest budget that keeps rows over 2048 tokens at the ~3%% rate the "
            "published suite already accepts; see the module docstring."
        ),
    )
    parser.add_argument(
        "--v4-benchmark",
        default="data/processed/secure_code_relational_benchmark_v4.jsonl",
        help="checked for pair/slice/gold parity so the ablation stays single-variable",
    )
    parser.add_argument(
        "--output", default="data/processed/secure_code_relational_benchmark_v5.jsonl"
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_relational_benchmark_v5_summary.json",
    )
    args = parser.parse_args()

    all_rows: list[dict[str, Any]] = []
    summaries: dict[str, Any] = {}
    for source_value in args.source or DEFAULT_SOURCES:
        name, path = parse_source(source_value)
        defects = ingestion_defects(name, path)
        pairs, skipped, rejected_non_mirror = load_pairs(name, path)
        sampled = sample_representative(
            pairs, limit=args.pairs_per_source, seed=args.seed
        )
        # The invariant is re-validated at the *emitted* width, not only at the
        # n=3 width load_pairs used. Any new input format must re-prove this.
        non_mirror_at_width = sum(1 for p in sampled if not swap_mirror_is_exact(p))
        if non_mirror_at_width:
            raise SystemExit(
                f"source {name!r}: {non_mirror_at_width} sampled pairs fail the "
                f"exact-mirror invariant. Refusing to emit a suite with non-mirror pairs."
            )
        balanced = polarity_balanced_keys(sampled, seed=args.seed)
        all_rows.extend(
            build_rows(sampled, balanced=balanced, context_lines=args.context_lines)
        )
        eligible_plus_rejected = len(pairs) + rejected_non_mirror
        summaries[name] = {
            "input": str(path).replace("\\", "/"),
            "ingestion": defects,
            "eligible_pairs": len(pairs),
            "skipped_groups": skipped,
            "rejected_non_mirror_pairs": rejected_non_mirror,
            "non_mirror_rejection_rate": (
                rejected_non_mirror / eligible_plus_rejected
                if eligible_plus_rejected
                else 0.0
            ),
            "non_mirror_at_emitted_width": non_mirror_at_width,
            "sampled_pairs": len(sampled),
            "polarity_balanced_pairs": len(balanced),
        }

    parity = assert_parity_with_v4(all_rows, ROOT / args.v4_benchmark)

    summary = {
        "benchmark_version": "v5",
        "derived_from": "v4",
        "single_variable_change": {
            "field": "difflib unified-diff context lines (n)",
            "v4": 3,
            "v5": args.context_lines,
            "affects": "amount of unchanged surrounding code shown, in both rendering families",
            "does_not_affect": (
                "the +/- lines, therefore net character polarity, therefore the "
                "semantics-free control and the four (gold x net-sign) cells"
            ),
        },
        "parity_with_v4": parity,
        "rows": len(all_rows),
        "pairs": len(all_rows) // 4,
        "rendering_families": ["glyph", "prose"],
        "sources": summaries,
        "invariants": {
            "exact_swap_mirror": (
                "enforced at load AND re-validated at the emitted context width; "
                "a suite with any non-mirror pair is refused"
            ),
            "truncation_hazard": (
                "canonical and side_swap renderings of a pair do not truncate at "
                "the same point, so a row truncated by max_length is no longer an "
                "exact mirror. This is why the context budget is chosen to keep "
                "over-length rows rare rather than rendering whole units."
            ),
        },
        "shortcuts_NOT_removed": {
            "net_polarity_sign": (
                "unchanged from v4 by construction. Widening context cannot weaken "
                "the polarity control, which reads only +/- lines. The balanced "
                "slice remains the primary reporting surface, where the control "
                "sits at chance."
            ),
        },
    }

    write_jsonl(ROOT / args.output, all_rows)
    write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

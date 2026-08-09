"""Build the v4 purified relational suite.

v4 differs from v3 in four ways:

1. **Every source passes the exact-mirror invariant.** Rejections are counted by
   *cause* (single-line source records vs. non-mirror rendering) and published
   per source. A source that loses all pairs is a hard error.
2. **Both renderings are first-class.** The glyph family (unified diff) and the
   prose family (``split_view``) are materialized for every pair, so
   glyph->prose transfer is a primary measurement rather than a diagnostic.
3. **A polarity-balanced evaluation slice is emitted.** Rows carry
   ``polarity_balanced_slice``. Within that slice the sign of the net character
   change is uncorrelated with gold by construction, so the semantics-free
   control sits at chance and cannot win on the "fixes add code" regularity.
4. **The suite documents what it removed.** ``shortcuts_removed`` in the summary
   records each neutralised shortcut and how it was neutralised.

Note on what balancing does and does not do: stripping ``+``/``-`` glyphs does
**not** disadvantage the control -- the prose control scores the same as the
glyph control on identical pairs (see
``reports/SPLIT_VIEW_PROSE_CONTROL_CROSSVUL_V3.md``). The control's advantage
comes from the *statistical regularity that security fixes add characters*,
which survives any rendering that reveals edit direction. Only the balanced
slice removes it.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vrf.io_utils import write_json, write_jsonl
from vrf.nuisance_transfer import build_nuisance_rows
from vrf.polarity_control import diff_line_counts
from vrf.relational_benchmark import (
    is_line_structured,
    pair_metadata,
    render_pair,
    sample_representative,
    swap_pair,
)

from scripts.build_relational_benchmark_v2 import load_pairs, parse_source

DEFAULT_SOURCES = [
    "primevul=data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl",
    "deltasecommits=data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata_v2.jsonl",
    "patcheval=data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl",
    "crossvul=data/processed/secure_code_crossvul_pair_diff_eval_metadata.jsonl",
]


def ingestion_defects(name: str, path: Path) -> dict[str, Any]:
    """Count single-line source records before the invariant sees them."""

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    with (ROOT / path).open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            grouped[str(row.get("pair_key") or row["id"])].append(row)
    total = flat = 0
    for rows in grouped.values():
        if len(rows) != 2:
            continue
        total += 1
        if any(not is_line_structured(str(row.get("code") or "")) for row in rows):
            flat += 1
    return {
        "pairs_seen": total,
        "single_line_pairs": flat,
        "single_line_rate": flat / total if total else 0.0,
    }


def glyph_char_net(text: str) -> int:
    return diff_line_counts(text)["char_net"]


def polarity_balanced_keys(
    pairs: list[Any], *, seed: int
) -> set[tuple[str, str]]:
    """Largest subsample where sign(net chars) is independent of gold.

    Four cells -- (gold A|B) x (net +|-) -- are downsampled to the smallest.
    Pairs with a zero net change are excluded because they carry no sign.
    """

    cells: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for pair in pairs:
        net = glyph_char_net(render_pair(pair))
        if net == 0:
            continue
        gold = "A" if pair.side_a.vulnerable else "B"
        cells[(gold, "+" if net > 0 else "-")].append(pair)
    if len(cells) < 4:
        return set()
    size = min(len(v) for v in cells.values())
    rng = random.Random(seed)
    keep: set[tuple[str, str]] = set()
    for members in cells.values():
        for pair in rng.sample(members, size):
            keep.add((pair.dataset, pair.pair_key))
    return keep


def build_rows(pairs: list[Any], *, balanced: set[tuple[str, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for pair in pairs:
        metadata = pair_metadata(pair)
        in_slice = (pair.dataset, pair.pair_key) in balanced
        gold = "A" if pair.side_a.vulnerable else "B"
        flipped = "B" if gold == "A" else "A"

        glyph_canonical = render_pair(pair)
        glyph_swap = render_pair(swap_pair(pair))
        prose_canonical, prose_swap = build_nuisance_rows(pair, "split_view")

        # The glyph canonical rendering is the single base for the pair; the
        # other three are transformations of it. Exactly one row per base_id may
        # carry ``expected_relation == "identity"`` or runtime materialization
        # cannot resolve the base.
        base_id = f"v4::{pair.dataset}::{pair.pair_key}::glyph::canonical"

        for family, variant, text, side_gold, relation in (
            ("glyph", "canonical", glyph_canonical, gold, "identity"),
            ("glyph", "side_swap", glyph_swap, flipped, "equivariant"),
            ("prose", "canonical", prose_canonical, gold, "invariant"),
            ("prose", "side_swap", prose_swap, flipped, "equivariant"),
        ):
            rows.append(
                {
                    "id": f"v4::{pair.dataset}::{pair.pair_key}::{family}::{variant}",
                    "base_id": base_id,
                    "pair_key": pair.pair_key,
                    "dataset": pair.dataset,
                    **{k: v for k, v in metadata.items() if k not in ("id", "pair_key", "dataset")},
                    "rendering_family": family,
                    "audit_variant": f"{family}__{variant}"
                    if family == "prose"
                    else variant,
                    "transformation_family": family,
                    "transformation_template": f"v4_{family}_{variant}",
                    "expected_relation": relation,
                    "gold_riskier_side": side_gold,
                    "polarity_balanced_slice": in_slice,
                    "runtime_transform": {},
                    "text": text,
                }
            )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", action="append", default=None)
    parser.add_argument("--pairs-per-source", type=int, default=350)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--output", default="data/processed/secure_code_relational_benchmark_v4.jsonl"
    )
    parser.add_argument(
        "--summary-output", default="reports/secure_code_relational_benchmark_v4_summary.json"
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
        balanced = polarity_balanced_keys(sampled, seed=args.seed)
        all_rows.extend(build_rows(sampled, balanced=balanced))
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
            "sampled_pairs": len(sampled),
            "polarity_balanced_pairs": len(balanced),
            "polarity_balanced_fraction": (
                len(balanced) / len(sampled) if sampled else 0.0
            ),
        }

    summary = {
        "benchmark_version": "v4",
        "rows": len(all_rows),
        "pairs": len(all_rows) // 4,
        "rendering_families": ["glyph", "prose"],
        "sources": summaries,
        "invariants": {
            "exact_swap_mirror": "enforced at load; non-mirror pairs rejected, rates published per source",
            "line_structured_sources": "counted per source via is_line_structured; single-line records are an ingestion defect",
            "autojunk": (
                "difflib default (autojunk=True) retained. Measured on CrossVul: "
                "autojunk=False would recover 128 of 153 rejected pairs (+3.0%) but "
                "changes the rendering of 477/4218 (11.3%) currently-valid pairs, "
                "invalidating every existing prediction artifact. The exact-mirror "
                "filter is the cheaper and safer control."
            ),
        },
        "shortcuts_removed": {
            "malformed_side_swap": "pairs whose swapped rendering is not an exact mirror are rejected, so side-swap metrics are always well-defined",
            "net_polarity_sign": (
                "the polarity_balanced_slice equalises the four (gold x net-sign) cells, "
                "so the sign of the net character change carries no information about gold "
                "and the semantics-free control sits at chance"
            ),
        },
        "shortcuts_NOT_removed": {
            "glyph_encoding": (
                "stripping +/- glyphs does NOT weaken the control: a prose control reading "
                "the split_view block headers scores the same as the glyph control on the "
                "same pairs (0.8029 vs 0.8057 on CrossVul). The prose family exists to "
                "measure glyph->prose transfer, not to handicap the control."
            ),
            "net_polarity_magnitude": (
                "within the balanced slice a threshold rule refit on |net chars| still "
                "reaches ~0.58-0.59 (eval-set refit, so an optimistic upper bound). "
                "Magnitude stratification is the next lever if that residual matters."
            ),
        },
    }

    write_jsonl(ROOT / args.output, all_rows)
    write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Build prose-native training data for the v4 purified protocol.

Emits the same schema the antisymmetric trainer consumes (``pair_key``,
``label``, ``text``), but renders each pair with the ``split_view`` prose
rendering instead of a unified diff, so the ``+``/``-`` glyph channel is absent
from training.

Each pair contributes exactly two rows -- the canonical rendering and its side
swap -- with ``label = 1`` iff the riskier side of that rendering is B. This
matches ``secure_code_primevul_joint_side_choice_train_v1.jsonl``, where the two
rows of a pair are the forward and reverse orientations.

Guarantees enforced here:

* every pair satisfies ``swap_mirror_is_exact``;
* every pair is line-structured at ingestion (``is_line_structured``);
* **no pair appears in any v4 evaluation source** -- the held-out keys are read
  from the v4 suite itself rather than assumed;
* **no pair repeats the CONTENT of a held-out pair under a different key**, and
  no two admitted pairs share content. Key-based exclusion alone is not
  sufficient: PatchEval, DeltaSecommits and CrossVul assign several keys to
  identical content, which let 127 content-twins of v4 evaluation pairs into the
  pool and 32 of them into the published seed-7 balanced training set. See
  ``vrf.relational_benchmark.pair_content_fingerprint`` and
  ``reports/v4_suite_content_leak_check.json``.

``--prose-fraction`` controls the mixture. A pair is rendered entirely in one
family so that its two rows stay comparable; the fraction selects how many pairs
get prose.
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

from vrf.io_utils import read_jsonl, write_json, write_jsonl
from vrf.nuisance_transfer import build_nuisance_rows
from vrf.polarity_control import diff_line_counts
from vrf.relational_benchmark import (
    DEFAULT_CONTEXT_LINES,
    build_canonical_pair,
    is_line_structured,
    pair_content_fingerprint,
    render_pair,
    swap_mirror_is_exact,
    swap_pair,
)


def held_out_keys(suite: Path) -> set[str]:
    return {str(row["pair_key"]) for row in read_jsonl(suite)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        action="append",
        help="repeatable, name=path. Defaults to the PrimeVul time-disjoint train split.",
    )
    parser.add_argument(
        "--polarity-balanced",
        action="store_true",
        help=(
            "downsample to equal (gold x net-sign) cells so the net-polarity "
            "shortcut carries no gradient. Costs ~70%% of pairs."
        ),
    )
    parser.add_argument(
        "--held-out-suite",
        action="append",
        help=(
            "repeatable. Every pair_key in these files is excluded from training. "
            "Pass the v4 suite AND the full evaluation pools it was sampled from, "
            "not just the sampled subset."
        ),
    )
    parser.add_argument(
        "--context-lines",
        type=int,
        default=DEFAULT_CONTEXT_LINES,
        help=(
            "difflib unified-diff context budget for the rendered training text. "
            "Default 3 reproduces every published training set byte-for-byte; "
            "pass 32 to match the v5 wide-context suite."
        ),
    )
    parser.add_argument("--prose-fraction", type=float, default=1.0)
    parser.add_argument("--max-pairs", type=int)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument(
        "--output", default="data/processed/secure_code_prose_native_train_v1.jsonl"
    )
    parser.add_argument(
        "--summary-output", default="reports/secure_code_prose_native_train_v1_summary.json"
    )
    args = parser.parse_args()

    held_out_sources = args.held_out_suite or [
        "data/processed/secure_code_relational_benchmark_v4.jsonl"
    ]
    excluded: set[str] = set()
    for source in held_out_sources:
        excluded |= held_out_keys(ROOT / source)

    sources = args.source or [
        "primevul=data/processed/secure_code_primevul_pair_diff_time_train_le2020_balanced_6000_metadata.jsonl"
    ]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    dataset_of: dict[str, str] = {}
    for spec in sources:
        name, path = spec.split("=", 1) if "=" in spec else ("primevul", spec)
        for row in read_jsonl(ROOT / path):
            key = f"{name}::{row.get('pair_key') or row['id']}"
            grouped[key].append(row)
            dataset_of[key] = name

    stats = {
        "source_pairs": len(grouped),
        "excluded_held_out": 0,
        "excluded_held_out_content": 0,
        "excluded_duplicate_content": 0,
        "excluded_bad_structure": 0,
        "excluded_non_mirror": 0,
        "excluded_flat_records": 0,
    }

    # Pass 1: fingerprint every held-out pair we can see, whether it reaches us
    # through a held-out suite or through a source file that also carries it.
    # Key-based exclusion alone lets a held-out pair back in under a second key,
    # which is not hypothetical -- see pair_content_fingerprint's docstring.
    held_out_fingerprints: set[str] = set()
    for scoped_key, rows in sorted(grouped.items()):
        pair_key = scoped_key.split("::", 1)[1]
        if len(rows) == 2 and (pair_key in excluded or scoped_key in excluded):
            held_out_fingerprints.add(pair_content_fingerprint(rows))
    for source in held_out_sources:
        held_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in read_jsonl(ROOT / source):
            if row.get("code") is not None:
                held_rows[str(row.get("pair_key") or row["id"])].append(row)
        for rows in held_rows.values():
            if len(rows) == 2:
                held_out_fingerprints.add(pair_content_fingerprint(rows))

    seen_fingerprints: set[str] = set()
    pairs = []
    for scoped_key, rows in sorted(grouped.items()):
        dataset = dataset_of[scoped_key]
        pair_key = scoped_key.split("::", 1)[1]
        if pair_key in excluded or scoped_key in excluded:
            stats["excluded_held_out"] += 1
            continue
        if len(rows) != 2:
            stats["excluded_bad_structure"] += 1
            continue
        fingerprint = pair_content_fingerprint(rows)
        if fingerprint in held_out_fingerprints:
            stats["excluded_held_out_content"] += 1
            continue
        if fingerprint in seen_fingerprints:
            stats["excluded_duplicate_content"] += 1
            continue
        if any(not is_line_structured(str(r.get("code") or "")) for r in rows):
            stats["excluded_flat_records"] += 1
            continue
        try:
            pair = build_canonical_pair(pair_key, rows, dataset=dataset)
        except ValueError:
            stats["excluded_bad_structure"] += 1
            continue
        if not swap_mirror_is_exact(pair):
            stats["excluded_non_mirror"] += 1
            continue
        seen_fingerprints.add(fingerprint)
        pairs.append(pair)

    rng = random.Random(args.seed)
    rng.shuffle(pairs)

    cell_counts_before: dict[str, int] = {}
    cell_counts_after: dict[str, int] = {}
    if args.polarity_balanced:
        cells: dict[tuple[str, str], list[Any]] = defaultdict(list)
        for pair in pairs:
            net = diff_line_counts(render_pair(pair))["char_net"]
            if net == 0:
                stats["excluded_zero_net"] = stats.get("excluded_zero_net", 0) + 1
                continue
            gold = "A" if pair.side_a.vulnerable else "B"
            cells[(gold, "+" if net > 0 else "-")].append(pair)
        cell_counts_before = {f"gold={k[0]},net={k[1]}": len(v) for k, v in sorted(cells.items())}
        if len(cells) < 4:
            raise SystemExit(f"cannot balance: only {len(cells)} of 4 cells populated")
        size = min(len(v) for v in cells.values())
        balanced: list[Any] = []
        for key in sorted(cells):
            balanced.extend(rng.sample(cells[key], size))
        cell_counts_after = {f"gold={k[0]},net={k[1]}": size for k in sorted(cells)}
        rng.shuffle(balanced)
        pairs = balanced

    if args.max_pairs:
        pairs = pairs[: args.max_pairs]

    prose_cutoff = int(round(len(pairs) * args.prose_fraction))
    out_rows: list[dict[str, Any]] = []
    family_counts = {"prose": 0, "glyph": 0}
    for index, pair in enumerate(pairs):
        family = "prose" if index < prose_cutoff else "glyph"
        family_counts[family] += 1
        if family == "prose":
            canonical_text, swap_text = build_nuisance_rows(
                pair, "split_view", context_lines=args.context_lines
            )
        else:
            canonical_text, swap_text = (
                render_pair(pair, context_lines=args.context_lines),
                render_pair(swap_pair(pair), context_lines=args.context_lines),
            )

        gold = "A" if pair.side_a.vulnerable else "B"
        flipped = "B" if gold == "A" else "A"

        # Net polarity is a property of the PAIR and is always read from the
        # glyph rendering: the prose rendering carries no +/- lines, so measuring
        # it there would report zero for every row. The swap rendering has the
        # mirrored sign (guaranteed by swap_mirror_is_exact).
        canonical_net = diff_line_counts(render_pair(pair))["char_net"]

        for variant, text, side, net in (
            ("canonical", canonical_text, gold, canonical_net),
            ("side_swap", swap_text, flipped, -canonical_net),
        ):
            out_rows.append(
                {
                    "id": f"prose_train::{pair.dataset}::{pair.pair_key}::{family}::{variant}",
                    "pair_key": pair.pair_key,
                    "source_pair_key": pair.pair_key,
                    "rendering_family": family,
                    "orientation": "observed" if variant == "canonical" else "synthetic_reverse",
                    "vulnerable_side": side,
                    "label": 1 if side == "B" else 0,
                    "net_char_polarity": int(net),
                    "polarity_sign": 1 if net > 0 else (-1 if net < 0 else 0),
                    "text": text,
                }
            )

    summary = {
        "sources": sources,
        "polarity_balanced": args.polarity_balanced,
        "cell_counts_before_balancing": cell_counts_before,
        "cell_counts_after_balancing": cell_counts_after,
        "held_out_suites": held_out_sources,
        "held_out_pair_keys": len(excluded),
        "exclusions": stats,
        "training_pairs": len(pairs),
        "training_rows": len(out_rows),
        "mixture": {
            "prose_fraction_requested": args.prose_fraction,
            "prose_pairs": family_counts["prose"],
            "glyph_pairs": family_counts["glyph"],
            "prose_fraction_actual": (
                family_counts["prose"] / len(pairs) if pairs else 0.0
            ),
        },
        "context_lines": args.context_lines,
        "seed": args.seed,
        "guarantees": [
            "every pair satisfies swap_mirror_is_exact",
            "every source record is line-structured",
            "zero overlap with the v4 evaluation suite, by pair_key AND by content",
            "no two admitted pairs share content under different keys",
        ],
        "held_out_content_fingerprints": len(held_out_fingerprints),
    }

    write_jsonl(ROOT / args.output, out_rows)
    write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

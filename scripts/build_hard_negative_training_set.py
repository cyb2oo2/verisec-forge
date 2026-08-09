"""Build a hard-negative-enriched polarity-balanced training set.

What "hard" means here, and why it is not what the phase brief assumed
--------------------------------------------------------------------
The brief proposed mining pairs whose *content difference is subtle*. Measured
on the v4 suite against the published 3B polarity-balanced checkpoint, that is
not where the model fails. Discordant accuracy by removed/added similarity
quartile is non-monotonic and the subtlest quartile is not the worst:

    Q1 sim 0.00-0.16  acc 0.2955      Q3 sim 0.49-0.74  acc 0.5227
    Q2 sim 0.16-0.48  acc 0.5227      Q4 sim 0.75-0.99  acc 0.3913

Splitting instead on whether one side of the edit is empty isolates the failure
almost completely:

    discordant, pure add/delete (one block empty)   n=28   acc 0.0714
    discordant, mixed edit                          n=150  acc 0.5000

So the aggregate discordant number is *chance on mixed edits* blended with
*systematic inversion on pure additions and deletions*. Those are the cases
where net polarity is maximally confident and wrong, and the model follows it
almost deterministically. They are the hard negatives worth mining.

Avoiding a newly-introduced shortcut
------------------------------------
Enriching pure add/delete pairs **only** in the discordant cells would make
"is one block empty?" predictive of gold -- a fresh surface heuristic, which the
phase constraints forbid. The enrichment block is therefore itself balanced over
the four ``(gold x net-sign)`` cells, so the pure/mixed feature carries no
gradient either. Both the polarity shortcut and the hardness marker stay
uninformative.

Construction
------------
base       the published 552/cell x 4 balanced set, reused verbatim so the
           comparison against the 0.4333 baseline is exact
hard block ``--per-cell`` pure add/delete pairs per (gold x net-sign) cell,
           repeated ``--oversample`` times
control    ``--control-block`` draws the same-sized block from *mixed* edits
           instead, holding set size and compute constant so the hardness
           effect is separable from "more data"

All pairs are real and already satisfy the exact-mirror invariant (enforced by
``load_pairs``); nothing is synthesised.
"""

from __future__ import annotations

import argparse
import collections
import json
import random
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vrf.io_utils import read_jsonl, write_json, write_jsonl
from vrf.nuisance_transfer import build_nuisance_rows
from vrf.polarity_control import diff_line_counts
from vrf.relational_benchmark import render_pair, swap_mirror_is_exact, swap_pair

from scripts.build_relational_benchmark_v2 import load_pairs, parse_source

DEFAULT_SOURCES = [
    "primevul=data/processed/secure_code_primevul_pair_diff_time_train_le2020_balanced_6000_metadata.jsonl",
    "patcheval=data/processed/secure_code_patcheval_pair_diff_all_metadata.jsonl",
    "deltasecommits=data/processed/secure_code_deltasecommits_pair_diff_cpp_all_metadata_v2.jsonl",
    "crossvul=data/processed/secure_code_crossvul_pair_diff_eval_metadata.jsonl",
]
DEFAULT_HELD_OUT = [
    "data/processed/secure_code_relational_benchmark_v4.jsonl",
    "data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_metadata.jsonl",
    "data/processed/secure_code_primevul_pair_diff_time_eval_ge2021_balanced_2000_metadata.jsonl",
    "data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl",
    "data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata_v2.jsonl",
]


def pair_facts(pair: Any) -> dict[str, Any]:
    counts = diff_line_counts(render_pair(pair))
    net = counts["char_net"]
    gold = "A" if pair.side_a.vulnerable else "B"
    return {
        "net": net,
        "gold": gold,
        "sign": "+" if net > 0 else ("-" if net < 0 else "0"),
        "pure": counts["added_chars"] == 0 or counts["removed_chars"] == 0,
    }


def emit(pair: Any, facts: dict[str, Any], block: str, replica: int) -> list[dict[str, Any]]:
    canonical_text, swap_text = build_nuisance_rows(pair, "split_view")
    gold = facts["gold"]
    flipped = "B" if gold == "A" else "A"
    rows = []
    for variant, text, side, net in (
        ("canonical", canonical_text, gold, facts["net"]),
        ("side_swap", swap_text, flipped, -facts["net"]),
    ):
        rows.append(
            {
                "id": f"hardneg::{pair.dataset}::{pair.pair_key}::{block}{replica}::{variant}",
                "pair_key": f"{pair.pair_key}::{block}{replica}",
                "source_pair_key": pair.pair_key,
                "rendering_family": "prose",
                "orientation": "observed" if variant == "canonical" else "synthetic_reverse",
                "vulnerable_side": side,
                "label": 1 if side == "B" else 0,
                "net_char_polarity": int(net),
                "polarity_sign": "+" if net > 0 else "-",
                "hard_block": block,
                "pure_add_delete": bool(facts["pure"]),
                "text": text,
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", action="append", default=None)
    parser.add_argument("--held-out-suite", action="append", default=None)
    parser.add_argument(
        "--base",
        default="data/processed/secure_code_polarity_balanced_train_scaled_v1.jsonl",
        help="published balanced set, reused verbatim as the base block",
    )
    parser.add_argument("--per-cell", type=int, default=75)
    parser.add_argument("--oversample", type=int, default=4)
    parser.add_argument(
        "--control-block",
        action="store_true",
        help="draw the enrichment block from mixed edits instead of pure add/delete, "
        "holding set size and compute constant",
    )
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", required=True)
    args = parser.parse_args()

    held: set[str] = set()
    for path in args.held_out_suite or DEFAULT_HELD_OUT:
        for row in read_jsonl(ROOT / path):
            held.add(str(row.get("pair_key") or row.get("id")))

    base_rows = list(read_jsonl(ROOT / args.base))
    base_keys = {str(r["source_pair_key"]) for r in base_rows}

    by_key: dict[str, Any] = {}
    for spec in args.source or DEFAULT_SOURCES:
        name, path = parse_source(spec)
        pairs, _, _ = load_pairs(name, path)
        for pair in pairs:
            by_key.setdefault(pair.pair_key, pair)

    # Candidate pool for the enrichment block: held-out-clean, non-zero net,
    # exact-mirror (re-checked), and of the requested edit shape.
    cells: dict[tuple[str, str], list[Any]] = collections.defaultdict(list)
    for key, pair in by_key.items():
        if key in held:
            continue
        facts = pair_facts(pair)
        if facts["sign"] == "0":
            continue
        if facts["pure"] == bool(args.control_block):
            continue  # keep pure for the hard block, mixed for the control block
        if not swap_mirror_is_exact(pair):
            continue
        cells[(facts["gold"], facts["sign"])].append(pair)

    if len(cells) < 4:
        raise SystemExit(f"enrichment pool covers only {len(cells)} of 4 cells")
    available = {f"gold={g},net={s}": len(v) for (g, s), v in sorted(cells.items(), key=str)}
    per_cell = min(args.per_cell, min(len(v) for v in cells.values()))

    rng = random.Random(args.seed)
    out_rows = list(base_rows)
    for row in out_rows:
        row.setdefault("hard_block", "base")
        row.setdefault("pure_add_delete", None)

    chosen: list[Any] = []
    for cell in sorted(cells, key=str):
        chosen.extend(rng.sample(cells[cell], per_cell))
    block_name = "control" if args.control_block else "hard"
    for replica in range(args.oversample):
        for pair in chosen:
            out_rows.extend(emit(pair, pair_facts(pair), block_name, replica))

    # Post-hoc verification: neither polarity nor the hardness marker may be
    # predictive of gold in the emitted set.
    cell_counts: collections.Counter = collections.Counter()
    pure_by_cell: collections.Counter = collections.Counter()
    for row in out_rows:
        if row["orientation"] != "observed":
            continue
        cell = (row["vulnerable_side"], row["polarity_sign"])
        cell_counts[cell] += 1
        if row.get("pure_add_delete"):
            pure_by_cell[cell] += 1

    write_jsonl(ROOT / args.output, out_rows)
    summary = {
        "base": args.base,
        "base_pairs": len(base_keys),
        "enrichment_block": block_name,
        "enrichment_edit_shape": "mixed_edit" if args.control_block else "pure_add_delete",
        "enrichment_available_per_cell": available,
        "enrichment_per_cell": per_cell,
        "enrichment_unique_pairs": len(chosen),
        "enrichment_oversample": args.oversample,
        "enrichment_emitted_pairs": len(chosen) * args.oversample,
        "total_pairs": len(out_rows) // 2,
        "total_rows": len(out_rows),
        "cell_counts_observed_orientation": {f"gold={g},net={s}": c for (g, s), c in sorted(cell_counts.items(), key=str)},
        "pure_add_delete_by_cell": {f"gold={g},net={s}": c for (g, s), c in sorted(pure_by_cell.items(), key=str)},
        "seed": args.seed,
        "guarantees": [
            "every enrichment pair satisfies swap_mirror_is_exact (re-checked at selection)",
            "no synthesis: all pairs are real records from the four sources",
            "zero overlap with the v4/v5 evaluation suite or any eval pool",
            "the enrichment block is balanced over the four (gold x net-sign) cells, "
            "so neither net polarity nor the pure/mixed marker is predictive of gold",
        ],
    }
    write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

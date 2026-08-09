"""Is the balanced-slice gain over the polarity control stable or slice-specific?

Re-drawing a balanced slice with a new seed is **not** an independent replication.
The two discordant cells are the limiting cells, so every draw uses them in full
and only the concordant half varies; measured overlap between seeds is ~58%.
Treating such draws as independent confirmations is the error withdrawn in
``docs/RESEARCH_INTEGRITY_REMEDIATION.md`` (five splits overlapping at Jaccard
0.52-0.56).

This script therefore runs four analyses, weakest to strongest:

1. **Seed distribution** -- K pooled balanced draws. Measures slice-to-slice
   variability, explicitly labelled as non-independent.
2. **Population estimator** -- because the control is exactly 0.5 on any balanced
   slice and the slice is 50/50 concordant/discordant by construction, the
   quantity the subsample estimates is
   ``0.5 * acc_concordant + 0.5 * acc_discordant - 0.5``
   evaluated over *all* clean pairs. This is the same estimand with no sampling
   noise and maximum power.
3. **Disjoint-half replication** -- pairs are split into two non-overlapping
   halves; the population estimator is computed in each. This is the only
   genuinely independent replication available from one suite.
4. **Per-cell decomposition** -- where the effect actually lives.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Any

from vrf.polarity_control import diff_line_counts
from vrf.stats_cluster import cluster_bootstrap, group_sign_test

ROOT = Path(__file__).resolve().parents[1]
TIE_SEED = 20260804


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _logit(probability: float) -> float:
    bounded = min(max(float(probability), 1e-9), 1 - 1e-9)
    return math.log(bounded / (1 - bounded))


def build_pairs(rows: list[dict[str, Any]], family: str) -> list[dict[str, Any]]:
    base_variant = "canonical" if family == "glyph" else "prose__canonical"
    swap_variant = "side_swap" if family == "glyph" else "prose__side_swap"
    canonical = {
        r["pair_key"]: r
        for r in rows
        if r["rendering_family"] == family and r["audit_variant"] == base_variant
    }
    swap = {
        r["pair_key"]: r
        for r in rows
        if r["rendering_family"] == family and r["audit_variant"] == swap_variant
    }
    # Net polarity is a property of the PAIR, not of the rendering. It is always
    # read from the glyph rendering so that the glyph and prose families are
    # balanced over identical pairs; the prose rendering carries no +/- glyphs,
    # so measuring it there would collapse every pair into the zero-net cell.
    glyph_net = {
        r["pair_key"]: diff_line_counts(r["text"])["char_net"]
        for r in rows
        if r["rendering_family"] == "glyph" and r["audit_variant"] == "canonical"
    }
    out = []
    for key, base in canonical.items():
        other = swap.get(key)
        if other is None:
            continue
        net = glyph_net.get(key, 0)
        if net == 0:
            continue
        out.append(
            {
                "pair_key": key,
                "dataset": base["dataset"],
                "gold": str(base["gold_riskier_side"]),
                "net_sign": "+" if net > 0 else "-",
                "base_id": base["id"],
                "swap_id": other["id"],
                "swap_gold": str(other["gold_riskier_side"]),
            }
        )
    return out


def antisym_correct(
    pair: dict[str, Any], predictions: dict[str, dict[str, Any]]
) -> bool | None:
    first, second = predictions.get(pair["base_id"]), predictions.get(pair["swap_id"])
    if not first or not second:
        return None
    if first.get("probability_b") is None or second.get("probability_b") is None:
        return None
    score = _logit(first["probability_b"]) - _logit(second["probability_b"])
    return ("B" if score > 0 else "A") == pair["gold"]


def independent_both_correct(
    pair: dict[str, Any], predictions: dict[str, dict[str, Any]]
) -> bool | None:
    first, second = predictions.get(pair["base_id"]), predictions.get(pair["swap_id"])
    if not first or not second:
        return None
    return (
        str(first["predicted_riskier_side"]) == pair["gold"]
        and str(second["predicted_riskier_side"]) == pair["swap_gold"]
    )


def cells_of(pairs: list[dict[str, Any]]) -> dict[tuple[str, str], list]:
    cells: dict[tuple[str, str], list] = defaultdict(list)
    for pair in pairs:
        cells[(pair["gold"], pair["net_sign"])].append(pair)
    return cells


def population_delta(pairs: list[dict[str, Any]], correct_fn) -> dict[str, Any]:
    """Balanced-slice delta over control, with no subsampling.

    On any sign-balanced slice the control is exactly 0.5 and the slice is half
    concordant / half discordant, so the estimand is
    ``0.5*acc_conc + 0.5*acc_disc - 0.5``.
    """

    concordant = [p for p in pairs if (p["gold"], p["net_sign"]) in (("A", "+"), ("B", "-"))]
    discordant = [p for p in pairs if (p["gold"], p["net_sign"]) in (("A", "-"), ("B", "+"))]

    def accuracy(sample):
        values = [correct_fn(p) for p in sample]
        values = [v for v in values if v is not None]
        return sum(values) / len(values) if values else 0.0

    acc_c, acc_d = accuracy(concordant), accuracy(discordant)
    return {
        "n_concordant": len(concordant),
        "n_discordant": len(discordant),
        "acc_concordant": round(acc_c, 4),
        "acc_discordant": round(acc_d, 4),
        "balanced_accuracy": round(0.5 * acc_c + 0.5 * acc_d, 4),
        "delta_vs_control": round(0.5 * acc_c + 0.5 * acc_d - 0.5, 4),
    }


def bootstrap_population_delta(pairs, correct_fn, *, seed: int = 20260727):
    """Cluster bootstrap over pairs, resampling each cell stratum separately."""

    concordant = [p for p in pairs if (p["gold"], p["net_sign"]) in (("A", "+"), ("B", "-"))]
    discordant = [p for p in pairs if (p["gold"], p["net_sign"]) in (("A", "-"), ("B", "+"))]
    groups = [("c", p) for p in concordant] + [("d", p) for p in discordant]

    def statistic(sample):
        c = [correct_fn(p) for tag, p in sample if tag == "c"]
        d = [correct_fn(p) for tag, p in sample if tag == "d"]
        c = [v for v in c if v is not None]
        d = [v for v in d if v is not None]
        acc_c = sum(c) / len(c) if c else 0.0
        acc_d = sum(d) / len(d) if d else 0.0
        return 0.5 * acc_c + 0.5 * acc_d - 0.5

    return cluster_bootstrap(groups, statistic, seed=seed)


def seed_distribution(pairs, correct_fn, *, seeds: int = 25) -> dict[str, Any]:
    cells = cells_of(pairs)
    size = min(len(v) for v in cells.values())
    deltas = []
    for seed in range(seeds):
        rng = random.Random(1000 + seed)
        drawn = []
        for members in cells.values():
            drawn.extend(rng.sample(members, size))
        values = [correct_fn(p) for p in drawn]
        values = [v for v in values if v is not None]
        deltas.append(sum(values) / len(values) - 0.5)
    deltas.sort()
    return {
        "draws": seeds,
        "slice_size": 4 * size,
        "delta_min": round(deltas[0], 4),
        "delta_median": round(deltas[len(deltas) // 2], 4),
        "delta_max": round(deltas[-1], 4),
        "delta_mean": round(sum(deltas) / len(deltas), 4),
        "fraction_positive": round(sum(1 for d in deltas if d > 0) / len(deltas), 4),
        "note": "NOT independent draws: the discordant cells are limiting and appear in full in every draw (~58% pair overlap between seeds).",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite",
        type=Path,
        default=ROOT / "data/processed/secure_code_relational_benchmark_v4_runtime1024.jsonl",
    )
    parser.add_argument("--baseline-predictions", type=Path, required=True)
    parser.add_argument("--repaired-predictions", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "reports/veripatch_rr_balanced_slice_replication.json",
    )
    args = parser.parse_args()

    rows = read_jsonl(args.suite)
    predictions = {
        "baseline": {str(r["id"]): r for r in read_jsonl(args.baseline_predictions)},
        "repaired": {str(r["id"]): r for r in read_jsonl(args.repaired_predictions)},
    }

    payload: dict[str, Any] = {"families": {}}
    for family in ("glyph", "prose"):
        pairs = build_pairs(rows, family)
        cells = cells_of(pairs)
        family_entry: dict[str, Any] = {
            "n_pairs_nonzero_net": len(pairs),
            "cell_sizes": {f"gold={k[0]},net={k[1]}": len(v) for k, v in sorted(cells.items())},
            "max_pooled_balanced_slice": 4 * min(len(v) for v in cells.values()),
            "systems": {},
        }
        for model in ("baseline", "repaired"):
            for readout, fn in (
                ("antisym", antisym_correct),
                ("independent", independent_both_correct),
            ):
                correct = lambda p, f=fn, m=model: f(p, predictions[m])
                entry = {
                    "population": population_delta(pairs, correct),
                    "bootstrap": bootstrap_population_delta(pairs, correct),
                    "seed_distribution": seed_distribution(pairs, correct),
                }
                # Disjoint-half replication: genuinely independent pair sets.
                rng = random.Random(2026)
                shuffled = sorted(pairs, key=lambda p: p["pair_key"])
                rng.shuffle(shuffled)
                half = len(shuffled) // 2
                entry["disjoint_half_a"] = population_delta(shuffled[:half], correct)
                entry["disjoint_half_b"] = population_delta(shuffled[half:], correct)
                wins = sum(1 for p in pairs if correct(p) is True)
                losses = sum(1 for p in pairs if correct(p) is False)
                entry["overall_pair_counts"] = {"correct": wins, "incorrect": losses}
                family_entry["systems"][f"{model}_{readout}"] = entry
        payload["families"][family] = family_entry

    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"wrote {args.output}\n")

    for family, entry in payload["families"].items():
        print(f"=== family={family}  pairs={entry['n_pairs_nonzero_net']}  "
              f"max pooled balanced slice={entry['max_pooled_balanced_slice']}")
        print(f"    cells: {entry['cell_sizes']}")
        for system, stats in entry["systems"].items():
            pop = stats["population"]
            boot = stats["bootstrap"]
            seed = stats["seed_distribution"]
            a, b = stats["disjoint_half_a"], stats["disjoint_half_b"]
            print(
                f"  {system:22s} pop delta={pop['delta_vs_control']:+.4f} "
                f"CI95=[{boot['ci95_low']:+.4f}, {boot['ci95_high']:+.4f}]  "
                f"conc={pop['acc_concordant']:.4f} disc={pop['acc_discordant']:.4f}"
            )
            print(
                f"  {'':22s} seed draws: median={seed['delta_median']:+.4f} "
                f"range=[{seed['delta_min']:+.4f}, {seed['delta_max']:+.4f}] "
                f"pos={seed['fraction_positive']:.2f}"
            )
            print(
                f"  {'':22s} disjoint halves: A={a['delta_vs_control']:+.4f} "
                f"(n={a['n_concordant']}+{a['n_discordant']})  "
                f"B={b['delta_vs_control']:+.4f} "
                f"(n={b['n_concordant']}+{b['n_discordant']})"
            )
        print()


if __name__ == "__main__":
    main()

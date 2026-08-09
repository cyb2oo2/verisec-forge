"""Structural control vs. learned systems on the polarity-balanced v4 slice.

Primary question: does any learned system exceed the semantics-free controls once
the net-polarity shortcut is neutralised by balancing?

Within ``polarity_balanced_slice`` the four (gold x net-sign) cells are equal, so
the sign rule is exactly `0.5` by construction on *both* renderings. Any system
scoring above chance there is using something other than net polarity sign.

Each system is evaluated on its own rendering family:

* glyph family (unified diff)  -- glyph control, models on glyph rows
* prose family (``split_view``) -- prose control, models on prose rows

Metrics are pair-clustered and reported for the balanced slice and the full clean
set side by side, stratified by source.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from pathlib import Path
from typing import Any, Iterable

from vrf.polarity_control import diff_line_counts
from vrf.stats_cluster import group_sign_test, paired_cluster_bootstrap_diff

ROOT = Path(__file__).resolve().parents[1]
TIE_SEED = 20260804

REMOVED_HEADER = "Removed from Side A (absent in Side B):"
ADDED_HEADER = "Added in Side B (absent in Side A):"
CONTEXT_HEADER = "Unchanged context:"

FAMILY_VARIANTS = {
    "glyph": ("canonical", "side_swap"),
    "prose": ("prose__canonical", "prose__side_swap"),
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"required artifact missing: {path}")
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def glyph_char_net(text: str) -> int:
    return diff_line_counts(text)["char_net"]


def prose_char_net(text: str) -> int:
    if REMOVED_HEADER not in text or ADDED_HEADER not in text:
        return 0
    removed = text.split(REMOVED_HEADER, 1)[1].split(ADDED_HEADER, 1)[0]
    added = text.split(ADDED_HEADER, 1)[1].split(CONTEXT_HEADER, 1)[0]

    def size(block: str) -> int:
        return sum(len(line.strip()) for line in block.split("\n") if line.strip())

    return size(added) - size(removed)


def _logit(probability: float) -> float:
    bounded = min(max(float(probability), 1e-9), 1 - 1e-9)
    return math.log(bounded / (1 - bounded))


def _mean(values: Iterable[bool]) -> float:
    items = list(values)
    return sum(1 for value in items if value) / len(items) if items else 0.0


def canonical_accuracy(sample, preds) -> float:
    return _mean(preds.get(b["id"]) == str(b["gold_riskier_side"]) for b, _ in sample)


def equivariance(sample, preds) -> float:
    return _mean(preds.get(b["id"]) != preds.get(s["id"]) for b, s in sample)


def both_correct(sample, preds) -> float:
    return _mean(
        preds.get(b["id"]) == str(b["gold_riskier_side"])
        and preds.get(s["id"]) == str(s["gold_riskier_side"])
        for b, s in sample
    )


METRICS = {
    "canonical_accuracy": canonical_accuracy,
    "side_swap_equivariance": equivariance,
    "both_directions_correct": both_correct,
}


def build_systems(
    rows: list[dict[str, Any]],
    family: str,
    predictions: dict[str, dict[str, dict[str, Any]]],
) -> tuple[dict[str, dict[str, str]], list]:
    base_variant, swap_variant = FAMILY_VARIANTS[family]
    canonical = {r["pair_key"]: r for r in rows if r["audit_variant"] == base_variant}
    swap = {r["pair_key"]: r for r in rows if r["audit_variant"] == swap_variant}
    groups = [(b, swap[k]) for k, b in canonical.items() if k in swap]

    net = glyph_char_net if family == "glyph" else prose_char_net
    rng = random.Random(TIE_SEED)
    control: dict[str, str] = {}
    for row in sorted(
        [r for pair in groups for r in pair], key=lambda r: r["id"]
    ):
        value = net(row["text"])
        control[row["id"]] = (
            "A" if value > 0 else ("B" if value < 0 else rng.choice(("A", "B")))
        )

    systems: dict[str, dict[str, str]] = {"control": control}
    for name, preds in predictions.items():
        systems[f"{name}_independent"] = {
            key: str(value["predicted_riskier_side"])
            for key, value in preds.items()
            if value.get("predicted_riskier_side") in ("A", "B")
        }
        antisym: dict[str, str] = {}
        for base, other in groups:
            first, second = preds.get(base["id"]), preds.get(other["id"])
            if not first or not second:
                continue
            if first.get("probability_b") is None or second.get("probability_b") is None:
                continue
            score = _logit(first["probability_b"]) - _logit(second["probability_b"])
            decision = "B" if score > 0 else "A"
            antisym[base["id"]] = decision
            antisym[other["id"]] = "A" if decision == "B" else "B"
        systems[f"{name}_antisym"] = antisym
    return systems, groups


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
        default=ROOT / "reports/veripatch_rr_balanced_slice_control.json",
    )
    args = parser.parse_args()

    all_rows = read_jsonl(args.suite)
    predictions = {
        "baseline": {str(r["id"]): r for r in read_jsonl(args.baseline_predictions)},
        "repaired": {str(r["id"]): r for r in read_jsonl(args.repaired_predictions)},
    }

    payload: dict[str, Any] = {
        "suite": str(args.suite).replace("\\", "/"),
        "slices": {},
    }

    for slice_name, row_filter in (
        ("balanced", lambda r: bool(r.get("polarity_balanced_slice"))),
        ("full", lambda r: True),
    ):
        rows = [r for r in all_rows if row_filter(r)]
        slice_entry: dict[str, Any] = {}
        for family in ("glyph", "prose"):
            family_rows = [r for r in rows if r["rendering_family"] == family]
            systems, groups = build_systems(family_rows, family, predictions)
            by_source: dict[str, list] = {"ALL": groups}
            for base, other in groups:
                by_source.setdefault(str(base["dataset"]), []).append((base, other))

            family_entry: dict[str, Any] = {}
            for source, sample in sorted(by_source.items()):
                results = {
                    "n_pairs": len(sample),
                    **{
                        system: {
                            metric: round(fn(sample, preds), 4)
                            for metric, fn in METRICS.items()
                        }
                        for system, preds in systems.items()
                    },
                }
                comparisons: dict[str, Any] = {}
                for system, preds in systems.items():
                    if system == "control":
                        continue
                    entry = {}
                    for metric in ("canonical_accuracy", "both_directions_correct"):
                        statistic = METRICS[metric]
                        stats = paired_cluster_bootstrap_diff(
                            sample,
                            lambda group, fn=statistic: fn(group, systems["control"]),
                            lambda group, fn=statistic, p=preds: fn(group, p),
                        )
                        wins = sum(
                            1
                            for group in sample
                            if statistic([group], preds)
                            > statistic([group], systems["control"])
                        )
                        losses = sum(
                            1
                            for group in sample
                            if statistic([group], preds)
                            < statistic([group], systems["control"])
                        )
                        stats["group_sign_test"] = group_sign_test(wins, losses)
                        entry[metric] = stats
                    comparisons[system] = entry
                family_entry[source] = {
                    "results": results,
                    "vs_control": comparisons,
                }
            slice_entry[family] = family_entry
        payload["slices"][slice_name] = slice_entry

    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"wrote {args.output}\n")

    order = [
        "control",
        "baseline_independent",
        "repaired_independent",
        "baseline_antisym",
        "repaired_antisym",
    ]
    for slice_name in ("balanced", "full"):
        for family in ("glyph", "prose"):
            entry = payload["slices"][slice_name][family]
            for source in ["ALL"] + sorted(k for k in entry if k != "ALL"):
                results = entry[source]["results"]
                print(
                    f"=== slice={slice_name:8s} family={family:5s} "
                    f"source={source:14s} n={results['n_pairs']}"
                )
                print(f"  {'system':24s} {'canonical':>10s} {'equivar':>9s} {'both':>8s}")
                for system in order:
                    if system not in results:
                        continue
                    values = results[system]
                    print(
                        f"  {system:24s} {values['canonical_accuracy']:>10.4f} "
                        f"{values['side_swap_equivariance']:>9.4f} "
                        f"{values['both_directions_correct']:>8.4f}"
                    )
                if source == "ALL":
                    for system, metrics in entry[source]["vs_control"].items():
                        for metric, stats in metrics.items():
                            sign = stats["group_sign_test"]
                            print(
                                f"    [{system} - control :: {metric:23s}] "
                                f"delta={stats['point']:+.4f} "
                                f"CI95=[{stats['ci95_low']:+.4f}, {stats['ci95_high']:+.4f}] "
                                f"p={sign['two_sided_p_value_display']}"
                            )
                print()


if __name__ == "__main__":
    main()

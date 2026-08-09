"""Prose control on ``split_view``: is the glyph-channel binding source-specific?

``split_view`` removes the ``+``/``-`` glyphs but states the same relation in
English ("Removed from Side A", "Added in Side B"). Two controls read the same
semantics-free quantity -- net added-minus-removed characters -- from the two
different encodings:

* **glyph control**  -- counts characters on ``+``/``-`` prefixed lines.
  On ``split_view`` there are none, so it has zero coverage by construction.
* **prose control**  -- parses the natural-language block headers instead.

If the prose control succeeds where the model fails, the information survived the
transformation and the model's collapse is an encoding failure, not an
information ablation.

Reports canonical accuracy, side-swap equivariance, and both-directions-correct,
pair-clustered, for every system on identical pairs.
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


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"required artifact missing: {path}")
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def prose_char_net(text: str) -> int | None:
    """Net added-minus-removed characters, read from the prose block headers."""

    if REMOVED_HEADER not in text or ADDED_HEADER not in text:
        return None
    removed = text.split(REMOVED_HEADER, 1)[1].split(ADDED_HEADER, 1)[0]
    added = text.split(ADDED_HEADER, 1)[1].split(CONTEXT_HEADER, 1)[0]

    def size(block: str) -> int:
        return sum(len(line.strip()) for line in block.split("\n") if line.strip())

    return size(added) - size(removed)


def glyph_char_net(text: str) -> int:
    return diff_line_counts(text)["char_net"]


def _logit(probability: float) -> float:
    bounded = min(max(float(probability), 1e-9), 1 - 1e-9)
    return math.log(bounded / (1 - bounded))


def decide(value: int | None, rng: random.Random) -> str:
    """Sign rule fitted on the training split (sign=+1, threshold=0)."""

    if value is None or value == 0:
        return rng.choice(("A", "B"))
    return "A" if value > 0 else "B"


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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nuisance-audit", type=Path, required=True)
    parser.add_argument("--baseline-predictions", type=Path, required=True)
    parser.add_argument("--repaired-predictions", type=Path, required=True)
    parser.add_argument(
        "--glyph-audit",
        type=Path,
        required=True,
        help="canonical unified-diff audit for the same pairs (glyph baseline)",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--label", default="crossvul")
    args = parser.parse_args()

    rows = read_jsonl(args.nuisance_audit)
    canonical = {
        r["pair_key"]: r for r in rows if r["audit_variant"] == "canonical__split_view"
    }
    swap = {
        r["pair_key"]: r for r in rows if r["audit_variant"] == "side_swap__split_view"
    }
    groups = [(b, swap[k]) for k, b in canonical.items() if k in swap]

    rng = random.Random(TIE_SEED)
    prose: dict[str, str] = {}
    glyph_on_split: dict[str, str] = {}
    prose_ties = glyph_ties = 0
    for row in sorted(
        (r for r in rows if r["audit_variant"].endswith("__split_view")),
        key=lambda r: r["id"],
    ):
        value = prose_char_net(row["text"])
        prose_ties += int(value is None or value == 0)
        prose[row["id"]] = decide(value, rng)
        glyph = glyph_char_net(row["text"])
        glyph_ties += int(glyph == 0)
        glyph_on_split[row["id"]] = decide(glyph, rng)

    systems: dict[str, dict[str, str]] = {
        "prose_control": prose,
        "glyph_control_on_split_view": glyph_on_split,
    }

    for name, path in (
        ("baseline", args.baseline_predictions),
        ("repaired", args.repaired_predictions),
    ):
        predictions = {str(r["id"]): r for r in read_jsonl(path)}
        systems[f"{name}_independent"] = {
            key: str(value["predicted_riskier_side"])
            for key, value in predictions.items()
            if value.get("predicted_riskier_side") in ("A", "B")
        }
        antisym: dict[str, str] = {}
        for base, other in groups:
            first, second = predictions.get(base["id"]), predictions.get(other["id"])
            if not first or not second:
                continue
            if first.get("probability_b") is None or second.get("probability_b") is None:
                continue
            score = _logit(first["probability_b"]) - _logit(second["probability_b"])
            decision = "B" if score > 0 else "A"
            antisym[base["id"]] = decision
            antisym[other["id"]] = "A" if decision == "B" else "B"
        systems[f"{name}_antisym"] = antisym

    # Glyph control on the ordinary unified-diff rendering of the same pairs.
    glyph_rows = read_jsonl(args.glyph_audit)
    glyph_canon = {r["pair_key"]: r for r in glyph_rows if r["audit_variant"] == "canonical"}
    glyph_swap = {r["pair_key"]: r for r in glyph_rows if r["audit_variant"] == "side_swap"}
    glyph_groups = [
        (glyph_canon[k], glyph_swap[k])
        for k, _ in canonical.items()
        if k in glyph_canon and k in glyph_swap
    ]
    glyph_reference: dict[str, str] = {}
    for row in sorted(
        [r for pair in glyph_groups for r in pair], key=lambda r: r["id"]
    ):
        glyph_reference[row["id"]] = decide(glyph_char_net(row["text"]), rng)

    payload: dict[str, Any] = {
        "label": args.label,
        "nuisance_audit": str(args.nuisance_audit).replace("\\", "/"),
        "glyph_audit": str(args.glyph_audit).replace("\\", "/"),
        "pairs_split_view": len(groups),
        "pairs_shared_with_glyph_audit": len(glyph_groups),
        "prose_control_tie_rate": prose_ties / (2 * len(groups)) if groups else 0.0,
        "glyph_control_zero_coverage_rate_on_split_view": (
            glyph_ties / (2 * len(groups)) if groups else 0.0
        ),
        "split_view": {
            system: {
                metric: round(fn(groups, preds), 4) for metric, fn in METRICS.items()
            }
            for system, preds in systems.items()
        },
        "glyph_control_on_canonical_rendering": {
            metric: round(fn(glyph_groups, glyph_reference), 4)
            for metric, fn in METRICS.items()
        },
        "clustered_vs_prose_control": {},
    }

    for system, preds in systems.items():
        if system == "prose_control":
            continue
        entry = {}
        for metric in ("canonical_accuracy", "both_directions_correct"):
            statistic = METRICS[metric]
            stats = paired_cluster_bootstrap_diff(
                groups,
                lambda group, fn=statistic: fn(group, systems["prose_control"]),
                lambda group, fn=statistic, p=preds: fn(group, p),
            )
            wins = sum(
                1
                for group in groups
                if statistic([group], preds) > statistic([group], systems["prose_control"])
            )
            losses = sum(
                1
                for group in groups
                if statistic([group], preds) < statistic([group], systems["prose_control"])
            )
            stats["group_sign_test"] = group_sign_test(wins, losses)
            entry[metric] = stats
        payload["clustered_vs_prose_control"][system] = entry

    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"wrote {args.output}\n")

    print(f"=== {args.label} split_view ({len(groups)} pairs)")
    print(f"  {'system':32s} {'canonical':>10s} {'equivar':>9s} {'both':>8s}")
    for system in (
        "prose_control",
        "glyph_control_on_split_view",
        "baseline_independent",
        "repaired_independent",
        "baseline_antisym",
        "repaired_antisym",
    ):
        values = payload["split_view"][system]
        print(
            f"  {system:32s} {values['canonical_accuracy']:>10.4f} "
            f"{values['side_swap_equivariance']:>9.4f} "
            f"{values['both_directions_correct']:>8.4f}"
        )
    reference = payload["glyph_control_on_canonical_rendering"]
    print(
        f"  {'[glyph control, canonical diff]':32s} "
        f"{reference['canonical_accuracy']:>10.4f} "
        f"{reference['side_swap_equivariance']:>9.4f} "
        f"{reference['both_directions_correct']:>8.4f}"
    )
    print(
        f"\n  prose tie rate={payload['prose_control_tie_rate']:.4f}  "
        f"glyph zero-coverage on split_view="
        f"{payload['glyph_control_zero_coverage_rate_on_split_view']:.4f}"
    )
    for system, metrics in payload["clustered_vs_prose_control"].items():
        for metric, stats in metrics.items():
            sign = stats["group_sign_test"]
            print(
                f"    [{system} - prose :: {metric:23s}] "
                f"delta={stats['point']:+.4f} "
                f"CI95=[{stats['ci95_low']:+.4f}, {stats['ci95_high']:+.4f}] "
                f"p={sign['two_sided_p_value_display']}"
            )


if __name__ == "__main__":
    main()

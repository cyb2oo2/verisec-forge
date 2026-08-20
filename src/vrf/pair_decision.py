"""Canonical pair construction and pair-level decision rules.

One constructor, one logit, one independent (per-rendering) decision, and one
antisymmetric projection. Report builders that need pair outcomes must call
this module instead of re-deriving the rules.

Independent decision
    Predict B iff ``p_B >= threshold`` (default 0.5). This is what a
    single-pass deployed system emits.

Antisymmetric projection
    Predict B iff ``logit(p_B | canonical) > logit(p_B | side_swap)``.
    Equivariance is exact by construction. This is a *score difference*,
    not a decision either rendering emits.

Semantics-free control
    Predict A iff glyph ``char_net > 0``, else B. Zero-net pairs are
    dropped by :func:`build_pairs`, matching
    ``scripts/replicate_balanced_slice_gain.py``.
"""

from __future__ import annotations

import math
from typing import Any, Iterable, Mapping

from vrf.polarity_control import diff_line_counts

CONCORDANT_CELLS: tuple[tuple[str, str], ...] = (("A", "+"), ("B", "-"))
DISCORDANT_CELLS: tuple[tuple[str, str], ...] = (("A", "-"), ("B", "+"))

ADMISSIBLE_SUITE_VERSIONS = frozenset({"v4", "v5"})

_DEFAULT_LOGIT_EPS = 1e-9


def logit(probability: float, *, eps: float = _DEFAULT_LOGIT_EPS) -> float:
    """Numerically stable logit. ``eps`` matches the existing analysis scripts."""

    bounded = min(max(float(probability), eps), 1.0 - eps)
    return math.log(bounded / (1.0 - bounded))


def independent_label(probability_b: float, *, threshold: float = 0.5) -> str:
    """Hard per-rendering decision: B iff ``p_B >= threshold``."""

    return "B" if float(probability_b) >= float(threshold) else "A"


def antisymmetric_label(
    canonical_probability_b: float, swap_probability_b: float
) -> str:
    """Sign of the pair-level score difference. Ties (exact 0) resolve to A."""

    score = logit(canonical_probability_b) - logit(swap_probability_b)
    return "B" if score > 0.0 else "A"


def control_label(char_net: int) -> str | None:
    """Semantics-free sign rule. ``None`` on a tie (zero net)."""

    if char_net > 0:
        return "A"
    if char_net < 0:
        return "B"
    return None


def cell_of(gold: str, net_sign: str) -> str:
    key = (gold, net_sign)
    if key in CONCORDANT_CELLS:
        return "concordant"
    if key in DISCORDANT_CELLS:
        return "discordant"
    raise ValueError(f"unknown (gold, net_sign) cell: {key!r}")


def family_variants(family: str) -> tuple[str, str]:
    if family == "glyph":
        return "canonical", "side_swap"
    if family == "prose":
        return "prose__canonical", "prose__side_swap"
    raise ValueError(f"unknown rendering family: {family!r}")


def build_pairs(rows: Iterable[Mapping[str, Any]], family: str) -> list[dict[str, Any]]:
    """Canonical/side-swap pairs for one rendering family, with pair net sign.

    Net polarity is a property of the pair and is always read from the glyph
    rendering. The prose rendering carries no ``+/-`` glyphs and would collapse
    every pair into the zero-net cell. Zero-net pairs are dropped.
    """

    base_variant, swap_variant = family_variants(family)
    canonical: dict[str, Mapping[str, Any]] = {}
    swap: dict[str, Mapping[str, Any]] = {}
    glyph_net: dict[str, int] = {}
    for row in rows:
        if row.get("rendering_family") == family and row.get("audit_variant") == base_variant:
            canonical[str(row["pair_key"])] = row
        if row.get("rendering_family") == family and row.get("audit_variant") == swap_variant:
            swap[str(row["pair_key"])] = row
        if (
            row.get("rendering_family") == "glyph"
            and row.get("audit_variant") == "canonical"
        ):
            glyph_net[str(row["pair_key"])] = int(diff_line_counts(str(row["text"]))["char_net"])

    out: list[dict[str, Any]] = []
    for key, base in canonical.items():
        other = swap.get(key)
        if other is None:
            continue
        net = int(glyph_net.get(key, 0))
        if net == 0:
            continue
        gold = str(base["gold_riskier_side"])
        net_sign = "+" if net > 0 else "-"
        out.append(
            {
                "pair_key": key,
                "dataset": base.get("dataset"),
                "balanced": bool(base.get("polarity_balanced_slice")),
                "gold": gold,
                "swap_gold": str(other["gold_riskier_side"]),
                "net": net,
                "net_sign": net_sign,
                "cell": cell_of(gold, net_sign),
                "control_label": control_label(net),
                "base_id": base["id"],
                "swap_id": other["id"],
            }
        )
    return out


def _probability_b(prediction: Mapping[str, Any]) -> float | None:
    value = prediction.get("probability_b")
    if value is None:
        probability_a = prediction.get("probability_a")
        if probability_a is None:
            return None
        return 1.0 - float(probability_a)
    return float(value)


def pair_scores(
    pair: Mapping[str, Any],
    predictions: Mapping[str, Mapping[str, Any]],
    *,
    threshold: float = 0.5,
) -> dict[str, Any] | None:
    """Independent, projected, and control outcomes for one pair."""

    first = predictions.get(str(pair["base_id"]))
    second = predictions.get(str(pair["swap_id"]))
    if not first or not second:
        return None
    canonical_p = _probability_b(first)
    swap_p = _probability_b(second)
    if canonical_p is None or swap_p is None:
        return None

    gold = str(pair["gold"])
    swap_gold = str(pair["swap_gold"])
    canonical_ind = independent_label(canonical_p, threshold=threshold)
    swap_ind = independent_label(swap_p, threshold=threshold)
    projected = antisymmetric_label(canonical_p, swap_p)
    control = pair.get("control_label") or control_label(int(pair["net"]))

    return {
        "canonical_p_b": canonical_p,
        "swap_p_b": swap_p,
        "canonical_logit": logit(canonical_p),
        "swap_logit": logit(swap_p),
        "projection_score": logit(canonical_p) - logit(swap_p),
        "independent_canonical": canonical_ind,
        "independent_swap": swap_ind,
        "antisym": projected,
        "control": control,
        "canonical_correct": canonical_ind == gold,
        "swap_correct": swap_ind == swap_gold,
        "both_correct": canonical_ind == gold and swap_ind == swap_gold,
        "frozen": canonical_ind == swap_ind,
        "antisym_correct": projected == gold,
        "control_correct": control == gold if control is not None else None,
        "projection_margin": abs(logit(canonical_p) - logit(swap_p)),
        "decision_margin": 0.5 * (abs(logit(canonical_p)) + abs(logit(swap_p))),
    }


def mean(values: Iterable[float]) -> float | None:
    items = [float(v) for v in values]
    if not items:
        return None
    return sum(items) / len(items)


def summarise_outcomes(outcomes: list[Mapping[str, Any]]) -> dict[str, Any]:
    if not outcomes:
        return {"n_pairs": 0}
    frozen = [o for o in outcomes if o["frozen"]]
    unfrozen = [o for o in outcomes if not o["frozen"]]
    control_values = [float(o["control_correct"]) for o in outcomes if o.get("control_correct") is not None]
    return {
        "n_pairs": len(outcomes),
        "antisym_accuracy": _round(mean([float(o["antisym_correct"]) for o in outcomes])),
        "independent_canonical_accuracy": _round(
            mean([float(o["canonical_correct"]) for o in outcomes])
        ),
        "independent_swap_accuracy": _round(
            mean([float(o["swap_correct"]) for o in outcomes])
        ),
        "independent_both_correct": _round(
            mean([float(o["both_correct"]) for o in outcomes])
        ),
        "side_swap_equivariance": _round(mean([float(not o["frozen"]) for o in outcomes])),
        "frozen_fraction": _round(mean([float(o["frozen"]) for o in outcomes])),
        "n_frozen": len(frozen),
        "antisym_accuracy_on_frozen": _round(
            mean([float(o["antisym_correct"]) for o in frozen])
        ),
        "antisym_accuracy_on_unfrozen": _round(
            mean([float(o["antisym_correct"]) for o in unfrozen])
        ),
        "control_accuracy": _round(mean(control_values)),
        "mean_projection_margin": _round(mean([float(o["projection_margin"]) for o in outcomes])),
        "mean_decision_margin": _round(mean([float(o["decision_margin"]) for o in outcomes])),
    }


def _round(value: float | None, digits: int = 4) -> float | None:
    return None if value is None else round(value, digits)

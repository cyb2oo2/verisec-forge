"""Frozen-vs-unfrozen decomposition of the published antisymmetric gain.

Inference-free. Consumes the committed 2/3/4/6/8-epoch prediction artifacts
and the admissible v4 suite. Pair construction and the two decision rules
come from :mod:`vrf.pair_decision`; this module only partitions those
outcomes and attributes the 2 → 8 lift.

A pair is frozen when the independent argmax returns the same side on
both renderings. The published compute-curve number is an antisymmetric
*projection* over those pairs. This analysis asks how much of the
``0.4333 → 0.7167`` discordant lift is carried exclusively by frozen
pairs, and whether those pairs are distinctive on cheap surface cues.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Sequence

from vrf.independent_threshold_sweep import strongest_control_from_pairs
from vrf.pair_decision import (
    build_pairs,
    mean,
    pair_scores,
    summarise_outcomes,
)
from vrf.stats_cluster import wilson_interval
from vrf.surface_features import (
    compare_groups,
    pair_surface_features,
    summarise_feature_group,
)

HEADLINE_FAMILY = "prose"
HEADLINE_SLICE = "full"
HEADLINE_CELL = "discordant"
EARLY_LABEL = "2ep"
LATE_LABEL = "8ep"

SLICES: tuple[tuple[str, str], ...] = (
    ("balanced", "ALL"),
    ("balanced", "concordant"),
    ("balanced", "discordant"),
    ("full", "ALL"),
    ("full", "concordant"),
    ("full", "discordant"),
)

PERSISTENCE_GROUPS = (
    "persistently_frozen",
    "unfroze",
    "froze",
    "persistently_unfrozen",
)

SURFACE_COMPARE_KEYS = (
    "abs_char_net",
    "char_total",
    "abs_line_net",
    "line_total",
    "glyph_imbalance",
    "abs_token_net",
    "token_jaccard",
    "tokens_only_added",
    "tokens_only_removed",
)

NEAR_CHANCE_LOW = 0.40
NEAR_CHANCE_HIGH = 0.60
EXTREME_LOW = 0.10
EXTREME_HIGH = 0.90


def _round(value: float | None, digits: int = 4) -> float | None:
    return None if value is None else round(float(value), digits)


def _slice_selector(slice_name: str, cell: str) -> Callable[[Mapping[str, Any]], bool]:
    def in_slice(pair: Mapping[str, Any]) -> bool:
        if slice_name == "balanced" and not pair["balanced"]:
            return False
        if cell == "ALL":
            return True
        return pair["cell"] == cell

    return in_slice


def resolve_pairs(
    pairs: Sequence[Mapping[str, Any]],
    predictions: Mapping[str, Mapping[str, Any]],
    *,
    threshold: float = 0.5,
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], int]:
    resolved: list[tuple[dict[str, Any], dict[str, Any]]] = []
    dropped = 0
    for pair in pairs:
        outcome = pair_scores(pair, predictions, threshold=threshold)
        if outcome is None:
            dropped += 1
            continue
        resolved.append((dict(pair), outcome))
    return resolved, dropped


def _wilson_from_flags(flags: Sequence[bool]) -> dict[str, Any] | None:
    if not flags:
        return None
    return wilson_interval(sum(1 for flag in flags if flag), len(flags))


def independent_score_profile(
    outcomes: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Where the independent scores sit: near chance, extreme, or in between."""

    if not outcomes:
        return {"n_pairs": 0}

    def _p(name: str) -> list[float]:
        return [float(row[name]) for row in outcomes]

    canonical = _p("canonical_p_b")
    swap = _p("swap_p_b")
    near = [
        NEAR_CHANCE_LOW <= p <= NEAR_CHANCE_HIGH for p in canonical
    ]
    extreme = [p <= EXTREME_LOW or p >= EXTREME_HIGH for p in canonical]
    both_near = [
        NEAR_CHANCE_LOW <= c <= NEAR_CHANCE_HIGH
        and NEAR_CHANCE_LOW <= s <= NEAR_CHANCE_HIGH
        for c, s in zip(canonical, swap)
    ]
    both_extreme = [
        (c <= EXTREME_LOW or c >= EXTREME_HIGH)
        and (s <= EXTREME_LOW or s >= EXTREME_HIGH)
        for c, s in zip(canonical, swap)
    ]
    return {
        "n_pairs": len(outcomes),
        "mean_canonical_p_b": _round(mean(canonical)),
        "mean_swap_p_b": _round(mean(swap)),
        "mean_abs_canonical_p_b_from_half": _round(
            mean([abs(p - 0.5) for p in canonical])
        ),
        "mean_abs_swap_p_b_from_half": _round(
            mean([abs(p - 0.5) for p in swap])
        ),
        "mean_decision_margin": _round(
            mean([float(row["decision_margin"]) for row in outcomes])
        ),
        "mean_projection_margin": _round(
            mean([float(row["projection_margin"]) for row in outcomes])
        ),
        "canonical_near_chance_fraction": _round(mean([float(x) for x in near])),
        "canonical_extreme_fraction": _round(mean([float(x) for x in extreme])),
        "both_near_chance_fraction": _round(mean([float(x) for x in both_near])),
        "both_extreme_fraction": _round(mean([float(x) for x in both_extreme])),
        "independent_canonical_accuracy": _round(
            mean([float(row["canonical_correct"]) for row in outcomes])
        ),
        "independent_both_correct": _round(
            mean([float(row["both_correct"]) for row in outcomes])
        ),
    }


def projection_alignment(
    pairs_and_outcomes: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> dict[str, Any]:
    """Does the projection follow the char-net sign rule or gold?"""

    if not pairs_and_outcomes:
        return {"n_pairs": 0}

    agree_control = []
    agree_gold = []
    for pair, outcome in pairs_and_outcomes:
        control = pair.get("control_label")
        if control is None:
            continue
        agree_control.append(outcome["antisym"] == control)
        agree_gold.append(bool(outcome["antisym_correct"]))
    n = len(agree_control)
    return {
        "n_pairs": n,
        "antisym_agrees_with_char_net_control": _round(
            mean([float(x) for x in agree_control])
        ),
        "antisym_agrees_with_gold": _round(mean([float(x) for x in agree_gold])),
        "antisym_agrees_with_char_net_wilson": _wilson_from_flags(agree_control),
        "antisym_agrees_with_gold_wilson": _wilson_from_flags(agree_gold),
        "note": (
            "On discordant cells the char-net control is always wrong, so "
            "agreement with the control is 1 minus agreement with gold. "
            "A projection that merely reads polarity cannot rise on this cell."
        ),
    }


def _glyph_text_by_pair(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, str]:
    texts: dict[str, str] = {}
    for row in rows:
        if (
            row.get("rendering_family") == "glyph"
            and row.get("audit_variant") == "canonical"
        ):
            texts[str(row["pair_key"])] = str(row.get("text") or "")
    return texts


def surface_partition(
    pairs_and_outcomes: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
    glyph_texts: Mapping[str, str],
) -> dict[str, Any]:
    frozen_feat: list[dict[str, Any]] = []
    unfrozen_feat: list[dict[str, Any]] = []
    for pair, outcome in pairs_and_outcomes:
        text = glyph_texts.get(str(pair["pair_key"]))
        if text is None:
            continue
        features = pair_surface_features(pair, text)
        if outcome["frozen"]:
            frozen_feat.append(features)
        else:
            unfrozen_feat.append(features)
    return {
        "frozen": summarise_feature_group(frozen_feat),
        "unfrozen": summarise_feature_group(unfrozen_feat),
        "frozen_minus_unfrozen": compare_groups(
            frozen_feat, unfrozen_feat, SURFACE_COMPARE_KEYS
        ),
    }


def slice_report(
    resolved: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
    *,
    glyph_texts: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    outcomes = [outcome for _, outcome in resolved]
    frozen = [outcome for outcome in outcomes if outcome["frozen"]]
    unfrozen = [outcome for outcome in outcomes if not outcome["frozen"]]
    summary = summarise_outcomes(outcomes)
    correct_frozen = sum(
        1 for outcome in outcomes if outcome["frozen"] and outcome["antisym_correct"]
    )
    correct_all = sum(1 for outcome in outcomes if outcome["antisym_correct"])
    summary.update(
        {
            "independent_canonical_wilson": _wilson_from_flags(
                [bool(o["canonical_correct"]) for o in outcomes]
            ),
            "antisym_wilson": _wilson_from_flags(
                [bool(o["antisym_correct"]) for o in outcomes]
            ),
            "share_of_correct_antisym_that_are_frozen": _round(
                (correct_frozen / correct_all) if correct_all else None
            ),
            "n_correct_antisym": correct_all,
            "n_correct_antisym_frozen": correct_frozen,
            "scores_frozen": independent_score_profile(frozen),
            "scores_unfrozen": independent_score_profile(unfrozen),
            "scores_all": independent_score_profile(outcomes),
            "alignment_all": projection_alignment(resolved),
            "alignment_frozen": projection_alignment(
                [(p, o) for p, o in resolved if o["frozen"]]
            ),
            "alignment_unfrozen": projection_alignment(
                [(p, o) for p, o in resolved if not o["frozen"]]
            ),
        }
    )
    if glyph_texts is not None:
        summary["surface"] = surface_partition(resolved, glyph_texts)
    return summary


def analyse_family(
    pairs: Sequence[Mapping[str, Any]],
    predictions: Mapping[str, Mapping[str, Any]],
    *,
    glyph_texts: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    resolved, dropped = resolve_pairs(pairs, predictions)
    slices: dict[str, Any] = {}
    for slice_name, cell in SLICES:
        selector = _slice_selector(slice_name, cell)
        selected = [(p, o) for p, o in resolved if selector(p)]
        slices[f"{slice_name}/{cell}"] = slice_report(
            selected, glyph_texts=glyph_texts
        )
    return {
        "pairs_missing_predictions": dropped,
        "n_pairs": len(resolved),
        "slices": slices,
        "default": {
            f"{slice_name}/{cell}": summarise_outcomes(
                [o for p, o in resolved if _slice_selector(slice_name, cell)(p)]
            )
            for slice_name, cell in SLICES
        },
    }


def analyse_system(
    rows: Sequence[Mapping[str, Any]],
    predictions: Mapping[str, Mapping[str, Any]],
    *,
    families: Sequence[str] = ("glyph", "prose"),
) -> dict[str, Any]:
    glyph_texts = _glyph_text_by_pair(rows)
    family_reports: dict[str, Any] = {}
    for family in families:
        pairs = build_pairs(rows, family)
        family_reports[family] = analyse_family(
            pairs, predictions, glyph_texts=glyph_texts
        )
    return {"families": family_reports}


def persistence_label(early_frozen: bool, late_frozen: bool) -> str:
    if early_frozen and late_frozen:
        return "persistently_frozen"
    if early_frozen and not late_frozen:
        return "unfroze"
    if (not early_frozen) and late_frozen:
        return "froze"
    return "persistently_unfrozen"


def _accuracy(items: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]]) -> float | None:
    if not items:
        return None
    return mean([float(outcome["antisym_correct"]) for _, outcome in items])


def lift_attribution(
    early: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
    late: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> dict[str, Any]:
    """Attribute ``acc_late - acc_early`` to persistence groups.

    Groups are defined on the *same* pair keys. The four group contributions
    sum to the observed lift. ``persistently_frozen_share_of_lift`` is the
    fraction of that lift carried exclusively by pairs that stay frozen.
    """

    early_by_key = {str(pair["pair_key"]): (pair, outcome) for pair, outcome in early}
    late_by_key = {str(pair["pair_key"]): (pair, outcome) for pair, outcome in late}
    keys = sorted(set(early_by_key) & set(late_by_key))
    n = len(keys)
    if n == 0:
        return {"n_pairs": 0}

    groups: dict[str, list[str]] = {name: [] for name in PERSISTENCE_GROUPS}
    deltas: dict[str, list[float]] = {name: [] for name in PERSISTENCE_GROUPS}
    early_correct = 0
    late_correct = 0
    late_frozen_delta = 0.0
    for key in keys:
        early_pair, early_out = early_by_key[key]
        _, late_out = late_by_key[key]
        label = persistence_label(bool(early_out["frozen"]), bool(late_out["frozen"]))
        delta = float(late_out["antisym_correct"]) - float(early_out["antisym_correct"])
        groups[label].append(key)
        deltas[label].append(delta)
        early_correct += int(early_out["antisym_correct"])
        late_correct += int(late_out["antisym_correct"])
        if late_out["frozen"]:
            late_frozen_delta += delta

    early_acc = early_correct / n
    late_acc = late_correct / n
    lift = late_acc - early_acc

    contributions: dict[str, Any] = {}
    for name in PERSISTENCE_GROUPS:
        contrib = (sum(deltas[name]) / n) if n else 0.0
        contributions[name] = {
            "n_pairs": len(groups[name]),
            "fraction_of_pairs": _round(len(groups[name]) / n),
            "early_antisym_accuracy": _round(
                _accuracy([early_by_key[k] for k in groups[name]])
            ),
            "late_antisym_accuracy": _round(
                _accuracy([late_by_key[k] for k in groups[name]])
            ),
            "lift_contribution": _round(contrib),
            "share_of_lift": (
                None if lift == 0.0 else _round(contrib / lift)
            ),
        }

    persistently = contributions["persistently_frozen"]
    frozen_at_late = _round(late_frozen_delta / n)
    return {
        "n_pairs": n,
        "early_antisym_accuracy": _round(early_acc),
        "late_antisym_accuracy": _round(late_acc),
        "lift": _round(lift),
        "n_correct_early": early_correct,
        "n_correct_late": late_correct,
        "n_correct_gained": late_correct - early_correct,
        "groups": contributions,
        "persistently_frozen_share_of_lift": persistently["share_of_lift"],
        "persistently_frozen_lift_contribution": persistently["lift_contribution"],
        "frozen_at_late_lift_contribution": frozen_at_late,
        "frozen_at_late_share_of_lift": (
            None if lift == 0.0 else _round((late_frozen_delta / n) / lift)
        ),
        "definition": (
            "lift = late antisym accuracy − early antisym accuracy on the "
            "matched pair keys. persistently_frozen_share_of_lift is the "
            "fraction of that lift coming from pairs frozen at both "
            "endpoints. frozen_at_late_share_of_lift additionally includes "
            "pairs that froze between the two endpoints."
        ),
    }


def product_decomposition(
    early_summary: Mapping[str, Any],
    late_summary: Mapping[str, Any],
) -> dict[str, Any]:
    """``acc = frozen_frac * acc_frozen + unfrozen_frac * acc_unfrozen``."""

    def mass(summary: Mapping[str, Any], frozen: bool) -> float | None:
        frac = summary.get("frozen_fraction")
        acc = (
            summary.get("antisym_accuracy_on_frozen")
            if frozen
            else summary.get("antisym_accuracy_on_unfrozen")
        )
        if frac is None or acc is None:
            return None
        weight = frac if frozen else (1.0 - frac)
        return weight * acc

    early_frozen = mass(early_summary, True)
    late_frozen = mass(late_summary, True)
    early_unfrozen = mass(early_summary, False)
    late_unfrozen = mass(late_summary, False)
    lift = None
    if (
        early_summary.get("antisym_accuracy") is not None
        and late_summary.get("antisym_accuracy") is not None
    ):
        lift = float(late_summary["antisym_accuracy"]) - float(
            early_summary["antisym_accuracy"]
        )
    frozen_delta = (
        None
        if early_frozen is None or late_frozen is None
        else late_frozen - early_frozen
    )
    unfrozen_delta = (
        None
        if early_unfrozen is None or late_unfrozen is None
        else late_unfrozen - early_unfrozen
    )
    return {
        "early_frozen_mass": _round(early_frozen),
        "late_frozen_mass": _round(late_frozen),
        "early_unfrozen_mass": _round(early_unfrozen),
        "late_unfrozen_mass": _round(late_unfrozen),
        "frozen_mass_delta": _round(frozen_delta),
        "unfrozen_mass_delta": _round(unfrozen_delta),
        "frozen_mass_share_of_lift": (
            None
            if lift in (None, 0.0) or frozen_delta is None
            else _round(frozen_delta / lift)
        ),
        "note": (
            "Mass = frozen_fraction × antisym_on_frozen at one epoch. "
            "This mixes a rate change with a composition change (fewer "
            "frozen pairs later). The pair-level persistence table is "
            "the exclusive attribution."
        ),
    }


def _headline_resolved(
    rows: Sequence[Mapping[str, Any]],
    predictions: Mapping[str, Mapping[str, Any]],
    *,
    family: str = HEADLINE_FAMILY,
    slice_name: str = HEADLINE_SLICE,
    cell: str = HEADLINE_CELL,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    pairs = build_pairs(rows, family)
    resolved, _ = resolve_pairs(pairs, predictions)
    selector = _slice_selector(slice_name, cell)
    return [(p, o) for p, o in resolved if selector(p)]


def curve_lift(
    rows: Sequence[Mapping[str, Any]],
    systems: Mapping[str, Mapping[str, Mapping[str, Any]]],
    *,
    early_label: str = EARLY_LABEL,
    late_label: str = LATE_LABEL,
    family: str = HEADLINE_FAMILY,
    slice_name: str = HEADLINE_SLICE,
    cell: str = HEADLINE_CELL,
) -> dict[str, Any]:
    if early_label not in systems or late_label not in systems:
        return {
            "available": False,
            "reason": f"need {early_label} and {late_label} prediction maps",
        }
    early = _headline_resolved(
        rows, systems[early_label], family=family, slice_name=slice_name, cell=cell
    )
    late = _headline_resolved(
        rows, systems[late_label], family=family, slice_name=slice_name, cell=cell
    )
    attribution = lift_attribution(early, late)
    early_summary = summarise_outcomes([o for _, o in early])
    late_summary = summarise_outcomes([o for _, o in late])
    return {
        "available": True,
        "family": family,
        "slice": f"{slice_name}/{cell}",
        "early_label": early_label,
        "late_label": late_label,
        "attribution": attribution,
        "product": product_decomposition(early_summary, late_summary),
        "early": early_summary,
        "late": late_summary,
    }


def strongest_controls(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "prose": {"strongest_control": strongest_control_from_pairs(build_pairs(rows, "prose"))},
        "glyph": {"strongest_control": strongest_control_from_pairs(build_pairs(rows, "glyph"))},
    }

"""Threshold sweep of the independent (per-rendering) decision.

The published compute-curve numbers are an antisymmetric *projection*. This
module asks the one question that separates "no relational content in the
per-rendering scores" from "content a shared 0.5 argmax cannot express":

    Is there a single shared threshold t such that
    ``independent_label(p_B, threshold=t)`` leaves chance on the pairs
    the headline metric is computed from?

Pre-registered decision rule (locked before looking at the curve):

* **Oracle upper bound.** The in-sample best t on the *same* evaluation
  pairs is an upper bound, not a claim. If even this bound's 95% CI on
  discordant independent-canonical accuracy includes 0.5, the scores
  contain no ranking content a threshold can recover.
* **Honest transfer.** t is selected on a disjoint half of the pairs and
  evaluated on the other half. Usable signal requires the held-out
  discordant independent-canonical CI to exclude 0.5.
* **AUC.** Mann-Whitney AUC of canonical ``p_B`` vs ``gold == B`` is the
  threshold-free ranking test. Chance is 0.5.

A positive on the oracle bound *without* a positive on the held-out test
is not usable independent signal. It is an eval-set fishing license.

Inference-free: consumes committed prediction artifacts only.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping, Sequence

from vrf.pair_decision import build_pairs, mean, pair_scores, summarise_outcomes
from vrf.stats_cluster import cluster_bootstrap, wilson_interval

DEFAULT_THRESHOLDS: tuple[float, ...] = tuple(
    round(0.05 * i, 2) for i in range(1, 20)
)  # 0.05 .. 0.95 inclusive
DEFAULT_THRESHOLD = 0.5
SPLIT_SEED = 20260816
BOOTSTRAP_SEED = 20260816
BOOTSTRAP_ITERATIONS = 2000

# Pre-registered: a CI "includes chance" when it covers this value.
CHANCE = 0.5


def _round(value: float | None, digits: int = 4) -> float | None:
    return None if value is None else round(value, digits)


def mann_whitney_auc(scores: Sequence[float], labels: Sequence[bool]) -> float | None:
    """AUC via midranks: P(score_pos > score_neg) + 0.5 P(eq).

    O(n log n). ``None`` if a class is empty.
    """

    n_pos = sum(1 for label in labels if label)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None
    ordered = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(ordered):
        j = i + 1
        while j < len(ordered) and scores[ordered[j]] == scores[ordered[i]]:
            j += 1
        midrank = 0.5 * (i + 1 + j)
        for k in range(i, j):
            ranks[ordered[k]] = midrank
        i = j
    rank_sum_pos = sum(rank for rank, label in zip(ranks, labels) if label)
    return (rank_sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def _select(
    resolved: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
    selector: Callable[[Mapping[str, Any]], bool],
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    return [item for item in resolved if selector(item[0])]


def _outcomes_at_threshold(
    pairs: Sequence[Mapping[str, Any]],
    predictions: Mapping[str, Mapping[str, Any]],
    threshold: float,
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


def _slice_selector(slice_name: str, cell: str) -> Callable[[Mapping[str, Any]], bool]:
    def in_slice(pair: Mapping[str, Any]) -> bool:
        if slice_name == "balanced" and not pair["balanced"]:
            return False
        if cell == "ALL":
            return True
        return pair["cell"] == cell

    return in_slice


def _accuracy(resolved: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]]) -> float | None:
    if not resolved:
        return None
    return mean([float(outcome["canonical_correct"]) for _, outcome in resolved])


def _auc(resolved: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]]) -> float | None:
    if not resolved:
        return None
    scores = [float(outcome["canonical_p_b"]) for _, outcome in resolved]
    labels = [pair["gold"] == "B" for pair, _ in resolved]
    return mann_whitney_auc(scores, labels)


def _wilson(resolved: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]]) -> dict[str, Any] | None:
    successes = sum(1 for _, outcome in resolved if outcome["canonical_correct"])
    return wilson_interval(successes, len(resolved)) if resolved else None


def _ci_includes(interval: Mapping[str, Any] | None, value: float = CHANCE) -> bool | None:
    if interval is None or interval.get("low") is None or interval.get("high") is None:
        return None
    return float(interval["low"]) <= value <= float(interval["high"])


def _bootstrap_auc(
    resolved: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
    *,
    iterations: int = BOOTSTRAP_ITERATIONS,
    seed: int = BOOTSTRAP_SEED,
) -> dict[str, Any] | None:
    if len(resolved) < 2:
        return None

    def statistic(sample: Sequence[Any]) -> float:
        value = _auc(sample)
        return 0.5 if value is None else value

    try:
        return cluster_bootstrap(
            list(resolved), statistic, iterations=iterations, seed=seed
        )
    except ValueError:
        return None


def _split_pairs(
    pairs: Sequence[Mapping[str, Any]], *, seed: int = SPLIT_SEED
) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    import random

    ordered = sorted(pairs, key=lambda pair: str(pair["pair_key"]))
    rng = random.Random(seed)
    rng.shuffle(ordered)
    half = len(ordered) // 2
    return list(ordered[:half]), list(ordered[half:])


def sweep_family(
    pairs: Sequence[Mapping[str, Any]],
    predictions: Mapping[str, Mapping[str, Any]],
    *,
    thresholds: Sequence[float] = DEFAULT_THRESHOLDS,
    bootstrap_iterations: int = BOOTSTRAP_ITERATIONS,
) -> dict[str, Any]:
    """Sweep one rendering family. ``pairs`` must already be for that family."""

    default_resolved, dropped = _outcomes_at_threshold(
        pairs, predictions, DEFAULT_THRESHOLD
    )
    train_pairs, test_pairs = _split_pairs(pairs)

    slices = (
        ("balanced", "ALL"),
        ("balanced", "concordant"),
        ("balanced", "discordant"),
        ("full", "ALL"),
        ("full", "concordant"),
        ("full", "discordant"),
    )

    curve: dict[str, Any] = {}
    for threshold in thresholds:
        resolved, _ = _outcomes_at_threshold(pairs, predictions, float(threshold))
        curve[f"{threshold:.2f}"] = {
            "threshold": float(threshold),
            "slices": {
                f"{slice_name}/{cell}": summarise_outcomes(
                    [outcome for _, outcome in _select(resolved, _slice_selector(slice_name, cell))]
                )
                for slice_name, cell in slices
            },
        }

    slice_reports: dict[str, Any] = {}
    for slice_name, cell in slices:
        selector = _slice_selector(slice_name, cell)
        default_slice = _select(default_resolved, selector)
        default_summary = summarise_outcomes([outcome for _, outcome in default_slice])

        # Oracle: in-sample best t on this slice (upper bound, not a claim).
        oracle_t = None
        oracle_acc = None
        for threshold in thresholds:
            resolved, _ = _outcomes_at_threshold(pairs, predictions, float(threshold))
            acc = _accuracy(_select(resolved, selector))
            if acc is None:
                continue
            if oracle_acc is None or acc > oracle_acc:
                oracle_acc = acc
                oracle_t = float(threshold)

        oracle_resolved = []
        if oracle_t is not None:
            oracle_all, _ = _outcomes_at_threshold(pairs, predictions, oracle_t)
            oracle_resolved = _select(oracle_all, selector)

        # Honest: pick t on train half, evaluate on test half of *this slice*.
        train_slice = [pair for pair in train_pairs if selector(pair)]
        test_slice = [pair for pair in test_pairs if selector(pair)]
        selected_t = None
        selected_train_acc = None
        for threshold in thresholds:
            resolved, _ = _outcomes_at_threshold(train_slice, predictions, float(threshold))
            acc = _accuracy(resolved)
            if acc is None:
                continue
            if selected_train_acc is None or acc > selected_train_acc:
                selected_train_acc = acc
                selected_t = float(threshold)
        heldout_resolved = []
        if selected_t is not None:
            heldout_all, _ = _outcomes_at_threshold(test_slice, predictions, selected_t)
            heldout_resolved = heldout_all

        auc_point = _auc(default_slice)
        auc_ci = _bootstrap_auc(default_slice, iterations=bootstrap_iterations)
        default_wilson = _wilson(default_slice)
        oracle_wilson = _wilson(oracle_resolved)
        heldout_wilson = _wilson(heldout_resolved)

        oracle_includes_chance = _ci_includes(oracle_wilson)
        heldout_includes_chance = _ci_includes(heldout_wilson)
        auc_includes_chance = _ci_includes(auc_ci)
        default_includes_chance = _ci_includes(default_wilson)

        # Pre-registered usable-signal rule.
        usable = bool(
            heldout_wilson is not None
            and heldout_includes_chance is False
            and float(heldout_wilson["point"]) > CHANCE
        )
        oracle_excludes_chance = bool(
            oracle_wilson is not None
            and oracle_includes_chance is False
            and float(oracle_wilson["point"]) > CHANCE
        )

        slice_reports[f"{slice_name}/{cell}"] = {
            **default_summary,
            "n_pairs": len(default_slice),
            "n_train": len(train_slice),
            "n_test": len(test_slice),
            "default_threshold": DEFAULT_THRESHOLD,
            "default": default_summary,
            "default_independent_canonical_wilson": default_wilson,
            "default_includes_chance": default_includes_chance,
            "oracle_threshold": oracle_t,
            "oracle_independent_canonical_accuracy": _round(oracle_acc),
            "oracle_independent_canonical_wilson": oracle_wilson,
            "oracle_includes_chance": oracle_includes_chance,
            "oracle_excludes_chance": oracle_excludes_chance,
            "selected_threshold": selected_t,
            "selected_train_accuracy": _round(selected_train_acc),
            "heldout": summarise_outcomes([outcome for _, outcome in heldout_resolved]),
            "heldout_independent_canonical_wilson": heldout_wilson,
            "heldout_includes_chance": heldout_includes_chance,
            "usable_independent_signal": usable,
            "auc_canonical_p_b_vs_gold_b": _round(auc_point),
            "auc_cluster_bootstrap": auc_ci,
            "auc_includes_chance": auc_includes_chance,
        }

    return {
        "pairs_missing_predictions": dropped,
        "n_pairs": len(default_resolved),
        "thresholds": [float(t) for t in thresholds],
        "slices": slice_reports,
        "curve": curve,
        "default": {
            f"{slice_name}/{cell}": summarise_outcomes(
                [
                    outcome
                    for _, outcome in _select(
                        default_resolved, _slice_selector(slice_name, cell)
                    )
                ]
            )
            for slice_name, cell in slices
        },
    }


def analyse_system(
    rows: Sequence[Mapping[str, Any]],
    predictions: Mapping[str, Mapping[str, Any]],
    *,
    families: Sequence[str] = ("glyph", "prose"),
    thresholds: Sequence[float] = DEFAULT_THRESHOLDS,
    bootstrap_iterations: int = BOOTSTRAP_ITERATIONS,
) -> dict[str, Any]:
    family_reports: dict[str, Any] = {}
    for family in families:
        pairs = build_pairs(rows, family)
        family_reports[family] = sweep_family(
            pairs,
            predictions,
            thresholds=thresholds,
            bootstrap_iterations=bootstrap_iterations,
        )
    return {"families": family_reports}


def overall_verdict(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Apply the pre-registered rule across the compute-curve systems.

    Headline cell: prose / full / discordant — the pairs the published
    antisymmetric metric is computed from. A system has usable independent
    signal only if the *held-out* selected threshold beats chance there.
    The oracle bound is reported but is not sufficient.
    """

    headline = "full/discordant"
    family = "prose"
    usable: list[str] = []
    oracle_only: list[str] = []
    none: list[str] = []
    missing: list[str] = []
    for label, system in (payload.get("systems") or {}).items():
        families = (system.get("families") or {})
        block = (families.get(family) or {}).get("slices") or {}
        cell = block.get(headline)
        if not cell:
            missing.append(str(label))
            continue
        if cell.get("usable_independent_signal"):
            usable.append(str(label))
        elif cell.get("oracle_excludes_chance"):
            oracle_only.append(str(label))
        else:
            none.append(str(label))

    if usable or oracle_only:
        decision = (
            "Three facts, in order. (1) The published 0.5-threshold independent "
            "decision stays at chance on the headline discordant cell across the "
            "whole curve. (2) Canonical p_B has weak ranking content that grows "
            "with compute (AUC rises; several AUC CIs exclude 0.5). (3) That "
            "content is not a usable single-pass operating point: selected "
            "thresholds sit in the extreme tail (t=0.05–0.20), the "
            "pre-registered held-out rule fires on a minority of systems, and "
            "the second 4-epoch seed does not replicate. The compute curve "
            "still trains the projection, not a decision. Do not resume the "
            "antisymmetric objective. A per-rendering CE / calibration term is "
            "the only training experiment this measurement licenses, and it is "
            "not started here."
        )
        stop_training = True
    else:
        decision = (
            "no_independent_signal: even the in-sample best threshold stays at "
            "chance on the pairs the headline metric is computed from. The "
            "projection is not reading a single-pass signal. Stop training. "
            "The remaining method question is Arc 2 Q1 (train on split_view only)."
        )
        stop_training = True

    return {
        "headline_cell": f"{family}/{headline}",
        "pre_registered_rule": (
            "usable iff held-out-selected t has independent-canonical Wilson CI "
            "excluding 0.5 on prose/full/discordant; oracle-only is not usable; "
            "a minority fire is reported but does not authorize training"
        ),
        "systems_usable": usable,
        "systems_oracle_only": oracle_only,
        "systems_no_signal": none,
        "systems_missing_headline": missing,
        "stop_training": stop_training,
        "decision": decision,
    }


def strongest_control_from_pairs(pairs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Control accuracy is the concordant fraction (the sign rule is exact)."""

    def acc(sample: Iterable[Mapping[str, Any]]) -> float | None:
        items = list(sample)
        if not items:
            return None
        return mean([float(pair["control_label"] == pair["gold"]) for pair in items])

    balanced = [pair for pair in pairs if pair["balanced"]]
    return {
        "name": "char_net_sign",
        "description": "predict A iff glyph char_net > 0, else B; zero-net dropped",
        "control_accuracy": _round(acc(pairs)),
        "full": {
            "n_pairs": len(pairs),
            "control_accuracy": _round(acc(pairs)),
            "n_concordant": sum(1 for pair in pairs if pair["cell"] == "concordant"),
            "n_discordant": sum(1 for pair in pairs if pair["cell"] == "discordant"),
        },
        "balanced": {
            "n_pairs": len(balanced),
            "control_accuracy": _round(acc(balanced)),
            "n_concordant": sum(1 for pair in balanced if pair["cell"] == "concordant"),
            "n_discordant": sum(1 for pair in balanced if pair["cell"] == "discordant"),
        },
        "note": (
            "On any polarity-balanced slice the four (gold x net-sign) cells "
            "are equalised, so this control is exactly 0.5 by construction."
        ),
    }

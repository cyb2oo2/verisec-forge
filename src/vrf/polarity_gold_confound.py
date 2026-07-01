"""Quantify the relationship between diff-hunk polarity and the gold label.

The side-order mechanism arc (reports/QWEN_POLARITY_ONLY_SWAP_VS_STRUCTURAL_SWAP.md)
shows the classifier's riskier-side decision is causally sensitive to diff-hunk
polarity. Whether that sensitivity is a *shortcut* depends on how polarity
relates to the gold label in the data the model saw and is scored on. This
module measures that relationship directly, so the claim boundary can rest on a
reported number rather than an implicit assumption.

Two distinct notions of "polarity" matter and must not be conflated:

* rendering orientation -- which side is the diff "from"/base side (rendered on
  ``-``/``---``). In VeriPatch-RR this is always Side A, and Side A/Side B are
  assigned independently of which side is vulnerable, so orientation is
  de-confounded from gold by construction.
* net changed-line polarity -- whether the rendered hunk is net-additive
  (more ``+`` than ``-`` changed lines) or net-subtractive. Real security fixes
  add guards/checks far more often than they delete code, so this feature is
  correlated with the vulnerable side even when orientation is balanced. It is
  the task-illegitimate-but-predictive feature a polarity-only swap flips.

Nothing here trains or runs a model; it is pure counting over existing rows.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable

__all__ = [
    "net_polarity",
    "orientation_balance",
    "polarity_gold_correlation",
    "model_shortcut_agreement",
]


def net_polarity(text: str) -> str:
    """Classify a rendered diff by net changed-line polarity.

    Returns ``"net_added"``, ``"net_removed"``, or ``"balanced"``. File-header
    markers (``+++``/``---``) are not changed lines and are excluded.
    """
    added = removed = 0
    for line in text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    if added > removed:
        return "net_added"
    if removed > added:
        return "net_removed"
    return "balanced"


def _norm_side(value: Any) -> str | None:
    text = str(value).upper()
    if text.startswith("A"):
        return "A"
    if text.startswith("B"):
        return "B"
    return None


def orientation_balance(
    rows: Iterable[dict[str, Any]],
    *,
    vulnerable_side_key: str = "vulnerable_side",
    orientation_key: str = "orientation",
    pair_key: str = "source_pair_key",
) -> dict[str, Any]:
    """Summarize whether rendering orientation is balanced against the gold side.

    Reports orientation counts, the fraction of rows whose vulnerable side is A
    (the "from"/base side), and how many source pairs carry more than one
    orientation. A balanced training set (``frac_vulnerable_side_a`` ~ 0.5 with
    every pair rendered in both orientations) means naive both-orientation
    augmentation is already present in the data.
    """
    rows = list(rows)
    orientations: Counter[str] = Counter()
    per_pair: dict[str, set[str]] = defaultdict(set)
    vuln_a = 0
    counted = 0
    for row in rows:
        orientation = str(row.get(orientation_key, "unknown"))
        orientations[orientation] += 1
        per_pair[str(row.get(pair_key, ""))].add(orientation)
        side = _norm_side(row.get(vulnerable_side_key))
        if side is not None:
            counted += 1
            vuln_a += side == "A"
    multi = sum(1 for variants in per_pair.values() if len(variants) >= 2)
    return {
        "rows": len(rows),
        "orientation_counts": dict(orientations),
        "labeled_rows": counted,
        "frac_vulnerable_side_a": (vuln_a / counted) if counted else None,
        "source_pairs": len(per_pair),
        "source_pairs_multi_orientation": multi,
    }


def polarity_gold_correlation(
    rows: Iterable[dict[str, Any]],
    *,
    text_key: str = "text",
    gold_key: str = "gold_riskier_side",
) -> dict[str, Any]:
    """Measure how well net changed-line polarity predicts the gold side.

    The naive shortcut is "net-added diff -> base/Side A is riskier; net-removed
    -> Side B". We report the conditional probabilities and the shortcut's
    accuracy on the non-balanced rows where it makes a call.
    """
    contingency: Counter[tuple[str, str]] = Counter()
    for row in rows:
        polarity = net_polarity(str(row.get(text_key, "")))
        gold = _norm_side(row.get(gold_key))
        if gold is None:
            continue
        contingency[(polarity, gold)] += 1

    na_a = contingency[("net_added", "A")]
    na_b = contingency[("net_added", "B")]
    nr_a = contingency[("net_removed", "A")]
    nr_b = contingency[("net_removed", "B")]
    bal_a = contingency[("balanced", "A")]
    bal_b = contingency[("balanced", "B")]

    added_total = na_a + na_b
    removed_total = nr_a + nr_b
    decided = added_total + removed_total
    # Shortcut predicts A on net_added and B on net_removed.
    shortcut_correct = na_a + nr_b
    return {
        "contingency": {
            "net_added": {"A": na_a, "B": na_b},
            "net_removed": {"A": nr_a, "B": nr_b},
            "balanced": {"A": bal_a, "B": bal_b},
        },
        "p_gold_a_given_net_added": (na_a / added_total) if added_total else None,
        "p_gold_a_given_net_removed": (nr_a / removed_total) if removed_total else None,
        "shortcut_decided_rows": decided,
        "shortcut_accuracy": (shortcut_correct / decided) if decided else None,
    }


def model_shortcut_agreement(
    rows: Iterable[dict[str, Any]],
    predictions: dict[str, dict[str, Any]],
    *,
    id_key: str = "id",
    text_key: str = "text",
    prediction_key: str = "predicted_riskier_side",
) -> dict[str, Any]:
    """Row-level agreement between the model and the net-polarity shortcut.

    High accuracy alignment in aggregate does not imply the model *implements*
    the shortcut. This measures per-row agreement so the report can state
    whether the model reduces to the crude line-count heuristic (it does not) or
    only shares its marginal accuracy.
    """
    agree = 0
    total = 0
    model_a = 0
    for row in rows:
        polarity = net_polarity(str(row.get(text_key, "")))
        if polarity == "balanced":
            continue
        prediction = predictions.get(str(row.get(id_key)))
        if prediction is None:
            continue
        model_side = _norm_side(prediction.get(prediction_key))
        if model_side is None:
            continue
        shortcut_side = "A" if polarity == "net_added" else "B"
        total += 1
        model_a += model_side == "A"
        agree += model_side == shortcut_side
    return {
        "n": total,
        "agreement": (agree / total) if total else None,
        "model_a_rate": (model_a / total) if total else None,
    }

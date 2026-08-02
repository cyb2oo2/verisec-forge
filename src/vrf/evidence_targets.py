"""Decision-independent evidence targets.

The original evidence pipeline defined its target with
``support_label_for_decision(decision=..., risk_support=..., safety_support=...)``,
which is antisymmetric in ``decision``: whenever ``risk_support != safety_support``
flipping the predicted side flips the target. Any "side-correct vs side-wrong"
comparison built on it therefore reports an identity of the labelling function
rather than a property of the evidence.

This module supplies the replacement contract. An evidence target must be a
function of the *evidence only*. It must not accept, or vary with, the decision
under evaluation.

Three roles are kept strictly separate:

``side prediction``
    which side of the pair the system believes is vulnerable (model output)
``evidence scoring``
    the ranking a scorer assigns to candidate hunks/windows (model output)
``evidence ground truth``
    where the vulnerability actually is (human adjudication; never model output)
"""

from __future__ import annotations

from typing import Any, Callable, Iterable

NEUTRAL = "neutral"
RISK_LEANING = "risk_leaning"
SAFETY_LEANING = "safety_leaning"


def evidence_polarity_label(*, risk_support: int, safety_support: int) -> str:
    """Classify a hunk by its own support balance, independent of any decision.

    This is a *description of the evidence*, not a correctness label. It does
    not know what the system predicted and cannot flip when the prediction
    flips.
    """

    if risk_support > safety_support:
        return RISK_LEANING
    if safety_support > risk_support:
        return SAFETY_LEANING
    return NEUTRAL


def is_decision_invariant(
    target_fn: Callable[..., Any],
    *,
    support_grid: Iterable[tuple[int, int]] = ((3, 1), (1, 3), (2, 2), (5, 0), (0, 5), (7, 4), (4, 7)),
) -> bool:
    """Return ``True`` when ``target_fn`` ignores the decision argument.

    ``target_fn`` is probed with ``decision=1`` and ``decision=0`` across a grid
    of support values. A target that changes when only the decision changes is
    not a valid evidence ground truth, because it encodes the thing being
    evaluated.

    Targets that do not accept a ``decision`` keyword at all are trivially
    invariant and return ``True``.
    """

    for risk, safety in support_grid:
        try:
            positive = target_fn(decision=1, risk_support=risk, safety_support=safety)
            negative = target_fn(decision=0, risk_support=risk, safety_support=safety)
        except TypeError:
            # Signature has no `decision` parameter: structurally invariant.
            return True
        if positive != negative:
            return False
    return True


def normalize_window_ids(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value.strip()} - {""})
    return frozenset(str(item).strip() for item in value if str(item).strip())


def human_evidence_windows(row: dict[str, Any]) -> frozenset[str] | None:
    """Extract adjudicated evidence windows, or ``None`` when unadjudicated.

    Only the adjudication block counts as ground truth. ``selected_window_ids``
    is the *pilot's* proposal (a model/pipeline output) and is deliberately not
    used as a target.
    """

    adjudication = row.get("adjudication")
    if not isinstance(adjudication, dict):
        return None
    if "final_evidence_window_ids" not in adjudication:
        return None
    return normalize_window_ids(adjudication.get("final_evidence_window_ids"))


def human_evidence_is_usable(row: dict[str, Any]) -> bool:
    """True when the adjudicator recorded a usable evidence span.

    Rows adjudicated ``insufficient_context`` carry no evidence location and are
    excluded from localization scoring rather than counted as misses.
    """

    adjudication = row.get("adjudication")
    if not isinstance(adjudication, dict):
        return False
    if adjudication.get("label_status") == "insufficient_context":
        return False
    windows = human_evidence_windows(row)
    return bool(windows)

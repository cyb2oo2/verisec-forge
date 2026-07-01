"""Score a set of predictions against the preregistered repair criteria.

Implements the pass/fail contract from `docs/REPAIR_EXPERIMENT_PREREGISTRATION.md`
so the same code evaluates (a) the current un-repaired checkpoint -- establishing
the baseline the repair must beat -- and (b) a future repaired model, with no
change to the decision rules between the two runs.

Consumes the polarity-audit shape: audit rows with ``audit_variant`` in
{canonical, polarity_only_swap, side_swap}, ``gold_riskier_side``, and a
predictions file with ``predicted_riskier_side`` (+ optional ``probability_a``).
No model is run.
"""

from __future__ import annotations

from typing import Any

from vrf.relational_evaluation import marginal_conditioned_violation_baseline

__all__ = ["evaluate_repair_criteria"]

_CANONICAL = "canonical"
_POLARITY = "polarity_only_swap"
_SIDE_SWAP = "side_swap"


def _norm(value: Any) -> str | None:
    text = str(value).upper()
    if text.startswith("A"):
        return "A"
    if text.startswith("B"):
        return "B"
    return None


def _by_pair(
    audit_rows: list[dict[str, Any]],
    predictions: dict[str, dict[str, Any]],
    variant: str,
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in audit_rows:
        if row.get("audit_variant") != variant:
            continue
        prediction = predictions.get(str(row["id"]))
        if prediction is None:
            continue
        out[str(row["pair_key"])] = {
            "pred": _norm(prediction.get("predicted_riskier_side")),
            "prob_a": prediction.get("probability_a"),
            "gold": _norm(row.get("gold_riskier_side")),
        }
    return out


def _accuracy(pairs: dict[str, dict[str, Any]]) -> float | None:
    scored = [p for p in pairs.values() if p["pred"] and p["gold"]]
    if not scored:
        return None
    return sum(p["pred"] == p["gold"] for p in scored) / len(scored)


def evaluate_repair_criteria(
    audit_rows: list[dict[str, Any]],
    predictions: dict[str, dict[str, Any]],
    *,
    canonical_noninferiority_margin: float = 0.02,
    baseline_canonical_accuracy: float | None = None,
) -> dict[str, Any]:
    """Compute the preregistered criteria and a pass/fail per criterion.

    ``baseline_canonical_accuracy`` is the pre-repair canonical accuracy; pass it
    when evaluating a repaired model so canonical non-inferiority is judged
    against the model being repaired. When omitted (baseline run) the
    non-inferiority check is reported as ``None`` (not applicable).
    """
    canonical = _by_pair(audit_rows, predictions, _CANONICAL)
    polarity = _by_pair(audit_rows, predictions, _POLARITY)
    side_swap = _by_pair(audit_rows, predictions, _SIDE_SWAP)

    canonical_acc = _accuracy(canonical)
    polarity_acc = _accuracy(polarity)
    side_swap_acc = _accuracy(side_swap)

    shared_pol = [k for k in canonical if k in polarity]
    shared_swap = [k for k in canonical if k in side_swap]

    # Polarity invariance: gold fixed, so the prediction should NOT change.
    polarity_flip_rate = None
    polarity_prob_gap = None
    if shared_pol:
        flips = 0
        gaps = []
        for k in shared_pol:
            if canonical[k]["pred"] and polarity[k]["pred"]:
                flips += canonical[k]["pred"] != polarity[k]["pred"]
            pa, pb = canonical[k]["prob_a"], polarity[k]["prob_a"]
            if pa is not None and pb is not None:
                gaps.append(abs(float(pa) - float(pb)))
        polarity_flip_rate = flips / len(shared_pol)
        polarity_prob_gap = sum(gaps) / len(gaps) if gaps else None

    # Build intervention rows for the violation-rate + marginal baseline.
    interventions = []
    for k in shared_pol:
        if canonical[k]["pred"] and polarity[k]["pred"]:
            interventions.append(
                {
                    "expected_relation": "invariant",
                    "base_prediction": canonical[k]["pred"],
                    "transformed_prediction": polarity[k]["pred"],
                    "base_protocol_valid": True,
                    "transformed_protocol_valid": True,
                    "relation_success": canonical[k]["pred"] == polarity[k]["pred"],
                }
            )
    for k in shared_swap:
        if canonical[k]["pred"] and side_swap[k]["pred"]:
            expected = "B" if canonical[k]["pred"] == "A" else "A"
            interventions.append(
                {
                    "expected_relation": "equivariant_swap",
                    "base_prediction": canonical[k]["pred"],
                    "transformed_prediction": side_swap[k]["pred"],
                    "base_protocol_valid": True,
                    "transformed_protocol_valid": True,
                    "relation_success": side_swap[k]["pred"] == expected,
                }
            )
    n_rel = len(interventions)
    violation_rate = (
        1.0 - sum(r["relation_success"] for r in interventions) / n_rel
        if n_rel
        else None
    )
    baseline = marginal_conditioned_violation_baseline(interventions)

    # Degeneracy: model A-rate across canonical (0.5 = balanced).
    canonical_a_rate = None
    scored_can = [p for p in canonical.values() if p["pred"]]
    if scored_can:
        canonical_a_rate = sum(p["pred"] == "A" for p in scored_can) / len(scored_can)

    def _passed() -> dict[str, Any]:
        checks: dict[str, Any] = {}
        # Canonical non-inferiority (only when a baseline is supplied).
        if baseline_canonical_accuracy is not None and canonical_acc is not None:
            delta = canonical_acc - baseline_canonical_accuracy
            checks["canonical_non_inferiority"] = delta >= -canonical_noninferiority_margin
        else:
            checks["canonical_non_inferiority"] = None
        # Polarity invariance: predictions should barely flip (gold fixed).
        checks["polarity_invariance"] = (
            polarity_flip_rate is not None and polarity_flip_rate <= 0.05
        )
        # Violation rate strictly below its marginal-conditioned baseline.
        base_v = baseline.get("baseline_violation_rate")
        checks["violation_below_baseline"] = (
            violation_rate is not None
            and base_v is not None
            and violation_rate < base_v
        )
        # No degeneracy: A-rate within [0.4, 0.6].
        checks["no_degeneracy"] = (
            canonical_a_rate is not None and 0.4 <= canonical_a_rate <= 0.6
        )
        return checks

    checks = _passed()
    return {
        "metrics": {
            "canonical_accuracy": canonical_acc,
            "polarity_only_accuracy": polarity_acc,
            "side_swap_accuracy": side_swap_acc,
            "polarity_flip_rate": polarity_flip_rate,
            "polarity_probability_gap": polarity_prob_gap,
            "relation_violation_rate": violation_rate,
            "marginal_conditioned_violation_baseline": baseline.get(
                "baseline_violation_rate"
            ),
            "canonical_model_a_rate": canonical_a_rate,
            "relation_rows": n_rel,
        },
        "criteria_passed": checks,
        "all_applicable_passed": all(
            v for v in checks.values() if v is not None
        ),
    }

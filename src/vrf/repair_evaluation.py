"""Score a set of predictions against the preregistered repair criteria.

Implements the pass/fail contract from `docs/REPAIR_EXPERIMENT_PREREGISTRATION.md`
so the same code evaluates (a) the current un-repaired checkpoint -- establishing
the baseline the repair must beat -- and (b) a future repaired model, with no
change to the decision rules between the two runs.

Consumes the polarity-audit shape: audit rows with ``audit_variant`` in
{canonical, polarity_only_swap, side_swap}, ``gold_riskier_side``, and a
predictions file with ``predicted_riskier_side`` (+ optional ``probability_a``).
No model is run.

Also provides ``antisymmetric_inference_correctness`` / ``exact_mcnemar`` /
``compare_antisymmetric_inference``: the projection-null decision
``s = g(canonical) - g(side_swap)`` and baseline-vs-repaired McNemar test used
to decompose the PrimeVul (#54) and CrossVul transfer results, formalized here
as tested functions so held-out nuisance-transform conditions
(`src/vrf/nuisance_transfer.py`) reuse the identical decomposition rather than
a re-derived metric.
"""

from __future__ import annotations

import math
from typing import Any

from vrf.relational_evaluation import marginal_conditioned_violation_baseline

__all__ = [
    "evaluate_repair_criteria",
    "antisymmetric_inference_correctness",
    "exact_mcnemar",
    "compare_antisymmetric_inference",
    "independent_inference_accuracy",
    "independent_inference_relation_violation",
]

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


def _logit(probability: float) -> float:
    p = min(max(float(probability), 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


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


def independent_inference_accuracy(
    audit_rows: list[dict[str, Any]],
    predictions: dict[str, dict[str, Any]],
    *,
    variant: str = _CANONICAL,
) -> float | None:
    """Plain per-rendering accuracy for ``variant`` (the un-repaired readout)."""
    return _accuracy(_by_pair(audit_rows, predictions, variant))


def independent_inference_relation_violation(
    audit_rows: list[dict[str, Any]],
    predictions: dict[str, dict[str, Any]],
    *,
    canonical_variant: str = _CANONICAL,
    side_swap_variant: str = _SIDE_SWAP,
) -> dict[str, Any]:
    """Side-swap equivariance violation rate for the independent (per-rendering)
    readout, against its marginal-conditioned baseline. Reuses
    ``marginal_conditioned_violation_baseline`` -- no new metric definition.
    """
    canonical = _by_pair(audit_rows, predictions, canonical_variant)
    side_swap = _by_pair(audit_rows, predictions, side_swap_variant)
    interventions = []
    for key in canonical:
        if key not in side_swap:
            continue
        if not canonical[key]["pred"] or not side_swap[key]["pred"]:
            continue
        expected = "B" if canonical[key]["pred"] == "A" else "A"
        interventions.append(
            {
                "expected_relation": "equivariant_swap",
                "base_prediction": canonical[key]["pred"],
                "transformed_prediction": side_swap[key]["pred"],
                "base_protocol_valid": True,
                "transformed_protocol_valid": True,
                "relation_success": side_swap[key]["pred"] == expected,
            }
        )
    n = len(interventions)
    violation_rate = (
        1.0 - sum(r["relation_success"] for r in interventions) / n if n else None
    )
    baseline = marginal_conditioned_violation_baseline(interventions)
    return {
        "n": n,
        "violation_rate": violation_rate,
        "marginal_conditioned_violation_baseline": baseline.get(
            "baseline_violation_rate"
        ),
    }


def antisymmetric_inference_correctness(
    audit_rows: list[dict[str, Any]],
    predictions: dict[str, dict[str, Any]],
    *,
    canonical_variant: str = _CANONICAL,
    side_swap_variant: str = _SIDE_SWAP,
) -> dict[str, Any]:
    """Per-pair correctness of the antisymmetric decision ``s = g(canonical) -
    g(side_swap)``, where ``g(text) = logit P(B riskier)`` from the model's own
    ``probability_b``.

    This is the "projection null" readout: side-swap equivariance is exact by
    construction (the decision depends only on the score difference, so
    swapping which rendering is fed as canonical negates the score), and the
    only empirical question is whether its accuracy differs between two
    models scored on the same pairs.
    """
    scores: dict[tuple[str, str], float] = {}
    gold: dict[str, str] = {}
    for row in audit_rows:
        variant = row.get("audit_variant")
        if variant not in (canonical_variant, side_swap_variant):
            continue
        prediction = predictions.get(str(row["id"]))
        if prediction is None or prediction.get("probability_b") is None:
            continue
        pair_key = str(row["pair_key"])
        scores[(pair_key, variant)] = _logit(prediction["probability_b"])
        if variant == canonical_variant:
            gold_side = _norm(row.get("gold_riskier_side"))
            if gold_side is not None:
                gold[pair_key] = gold_side

    correct: dict[str, bool] = {}
    for pair_key, gold_side in gold.items():
        if (pair_key, canonical_variant) in scores and (
            pair_key,
            side_swap_variant,
        ) in scores:
            score = (
                scores[(pair_key, canonical_variant)]
                - scores[(pair_key, side_swap_variant)]
            )
            predicted_side = "B" if score > 0 else "A"
            correct[pair_key] = predicted_side == gold_side
    n = len(correct)
    accuracy = sum(correct.values()) / n if n else None
    return {"n": n, "accuracy": accuracy, "correct_by_pair": correct}


def exact_mcnemar(
    baseline_correct: dict[str, bool], repaired_correct: dict[str, bool]
) -> dict[str, Any]:
    """Exact two-sided McNemar test on paired per-pair correctness dicts.

    ``fixed`` = pairs wrong under baseline, right under repaired.
    ``broken`` = pairs right under baseline, wrong under repaired.
    Only discordant pairs (fixed + broken) carry information; concordant pairs
    (both right or both wrong) do not affect the test.
    """
    keys = [key for key in baseline_correct if key in repaired_correct]
    fixed = sum(1 for key in keys if not baseline_correct[key] and repaired_correct[key])
    broken = sum(1 for key in keys if baseline_correct[key] and not repaired_correct[key])
    discordant = fixed + broken
    if discordant == 0:
        p_value = 1.0
    else:
        tail = sum(math.comb(discordant, i) for i in range(0, min(fixed, broken) + 1))
        p_value = min(1.0, tail / (2**discordant) * 2)
    return {
        "n_pairs": len(keys),
        "fixed": fixed,
        "broken": broken,
        "net": fixed - broken,
        "p_value": p_value,
    }


def compare_antisymmetric_inference(
    audit_rows: list[dict[str, Any]],
    baseline_predictions: dict[str, dict[str, Any]],
    repaired_predictions: dict[str, dict[str, Any]],
    *,
    canonical_variant: str = _CANONICAL,
    side_swap_variant: str = _SIDE_SWAP,
) -> dict[str, Any]:
    """Bundle the baseline-vs-repaired antisymmetric-inference decomposition:
    projection-null accuracy for both models, the fine-tuning delta over the
    null (``repaired - baseline``), and the exact McNemar test on paired
    per-pair correctness. Same computation used to decompose the PrimeVul
    (#54) and CrossVul transfer results.
    """
    baseline = antisymmetric_inference_correctness(
        audit_rows,
        baseline_predictions,
        canonical_variant=canonical_variant,
        side_swap_variant=side_swap_variant,
    )
    repaired = antisymmetric_inference_correctness(
        audit_rows,
        repaired_predictions,
        canonical_variant=canonical_variant,
        side_swap_variant=side_swap_variant,
    )
    mcnemar = exact_mcnemar(baseline["correct_by_pair"], repaired["correct_by_pair"])
    fine_tuning_delta = None
    if baseline["accuracy"] is not None and repaired["accuracy"] is not None:
        fine_tuning_delta = repaired["accuracy"] - baseline["accuracy"]
    return {
        "baseline_antisymmetric_accuracy": baseline["accuracy"],
        "repaired_antisymmetric_accuracy": repaired["accuracy"],
        "baseline_n": baseline["n"],
        "repaired_n": repaired["n"],
        "fine_tuning_delta_over_null": fine_tuning_delta,
        "mcnemar": mcnemar,
    }

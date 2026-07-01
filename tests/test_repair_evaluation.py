from vrf.repair_evaluation import evaluate_repair_criteria


def _row(pair, variant, gold):
    return {
        "id": f"{pair}::{variant}",
        "pair_key": pair,
        "audit_variant": variant,
        "gold_riskier_side": gold,
    }


def _pred(pair, variant, side, prob_a):
    return {"id": f"{pair}::{variant}", "predicted_riskier_side": side, "probability_a": prob_a}


def _build(pred_fn, n=20):
    """pred_fn(pair, variant, gold) -> (side, prob_a); gold alternates A/B."""
    audit, preds = [], {}
    for i in range(n):
        gold = "A" if i % 2 == 0 else "B"
        for variant in ("canonical", "polarity_only_swap", "side_swap"):
            audit.append(_row(f"p{i}", variant, gold))
            side, prob_a = pred_fn(f"p{i}", variant, gold)
            p = _pred(f"p{i}", variant, side, prob_a)
            preds[p["id"]] = p
    return audit, preds


def test_perfect_repair_passes_all_criteria():
    # Content-tracking model: predicts gold everywhere, invariant to polarity,
    # equivariant under side swap (side_swap gold is the flipped label, but a
    # content-correct model still names the same *content*, i.e. same side).
    def pred_fn(pair, variant, gold):
        return gold, (0.9 if gold == "A" else 0.1)

    audit, preds = _build(pred_fn)
    result = evaluate_repair_criteria(audit, preds, baseline_canonical_accuracy=0.66)
    m = result["metrics"]
    assert m["canonical_accuracy"] == 1.0
    assert m["polarity_flip_rate"] == 0.0
    assert result["criteria_passed"]["polarity_invariance"] is True
    assert result["criteria_passed"]["no_degeneracy"] is True
    assert result["criteria_passed"]["canonical_non_inferiority"] is True


def test_polarity_bound_model_fails_invariance_and_baseline():
    # Model flips its answer whenever polarity flips (polarity_only + side_swap
    # both carry flipped diff bodies).
    def pred_fn(pair, variant, gold):
        if variant == "canonical":
            return gold, 0.8 if gold == "A" else 0.2
        flipped = "B" if gold == "A" else "A"
        return flipped, 0.2 if gold == "A" else 0.8

    audit, preds = _build(pred_fn)
    result = evaluate_repair_criteria(audit, preds)
    assert result["criteria_passed"]["polarity_invariance"] is False
    assert result["criteria_passed"]["violation_below_baseline"] is False
    assert result["all_applicable_passed"] is False


def test_constant_predictor_flagged_degenerate():
    def pred_fn(pair, variant, gold):
        return "A", 0.99

    audit, preds = _build(pred_fn)
    result = evaluate_repair_criteria(audit, preds)
    assert result["criteria_passed"]["no_degeneracy"] is False

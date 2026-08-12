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


def _antisym_row(pair, variant, gold=None):
    row = {"id": f"{pair}::{variant}", "pair_key": pair, "audit_variant": variant}
    if gold is not None:
        row["gold_riskier_side"] = gold
    return row


def _antisym_pred(pair, variant, probability_b):
    return {"id": f"{pair}::{variant}", "probability_b": probability_b}


def test_antisymmetric_inference_correctness_content_tracking_model():
    from vrf.repair_evaluation import antisymmetric_inference_correctness

    # Content-tracking: g(canonical) strongly favors the true riskier side,
    # g(side_swap) strongly favors the swapped-in (wrong-for-canonical) side,
    # so s = g(canonical) - g(side_swap) should point at gold every time.
    audit = []
    preds = {}
    for i in range(10):
        gold = "A" if i % 2 == 0 else "B"
        audit.append(_antisym_row(f"p{i}", "canonical", gold))
        audit.append(_antisym_row(f"p{i}", "side_swap", gold))
        # canonical: strong signal toward gold; side_swap: strong signal away.
        prob_b_canonical = 0.05 if gold == "A" else 0.95
        prob_b_swap = 0.95 if gold == "A" else 0.05
        preds[f"p{i}::canonical"] = _antisym_pred(f"p{i}", "canonical", prob_b_canonical)
        preds[f"p{i}::side_swap"] = _antisym_pred(f"p{i}", "side_swap", prob_b_swap)

    result = antisymmetric_inference_correctness(audit, preds)
    assert result["n"] == 10
    assert result["accuracy"] == 1.0
    assert all(result["correct_by_pair"].values())


def test_antisymmetric_inference_correctness_ignores_rows_missing_probability_b():
    from vrf.repair_evaluation import antisymmetric_inference_correctness

    audit = [_antisym_row("p0", "canonical", "A"), _antisym_row("p0", "side_swap", "A")]
    preds = {"p0::canonical": {"id": "p0::canonical", "probability_b": 0.1}}  # side_swap missing
    result = antisymmetric_inference_correctness(audit, preds)
    assert result["n"] == 0
    assert result["accuracy"] is None


def test_exact_mcnemar_matches_known_primevul_and_crossvul_counts():
    from vrf.repair_evaluation import exact_mcnemar

    # PrimeVul decomposition from #54: 21 fixed, 5 broken, n=600 -> p ~= 0.0025.
    baseline = {f"p{i}": True for i in range(600)}
    repaired = dict(baseline)
    keys = list(baseline)
    for k in keys[:21]:
        baseline[k] = False  # wrong under baseline, right under repaired (fixed)
    for k in keys[21:26]:
        repaired[k] = False  # right under baseline, wrong under repaired (broken)
    result = exact_mcnemar(baseline, repaired)
    assert result["fixed"] == 21
    assert result["broken"] == 5
    assert result["n_pairs"] == 600
    assert abs(result["p_value"] - 0.0024939179420471) < 1e-9


def test_exact_mcnemar_symmetric_discordance_is_not_significant():
    from vrf.repair_evaluation import exact_mcnemar

    baseline = {"a": True, "b": False}
    repaired = {"a": False, "b": True}  # 1 fixed, 1 broken -> maximally non-significant
    result = exact_mcnemar(baseline, repaired)
    assert result["fixed"] == 1
    assert result["broken"] == 1
    assert result["p_value"] == 1.0


def test_exact_mcnemar_no_discordant_pairs_gives_p_one():
    from vrf.repair_evaluation import exact_mcnemar

    same = {"a": True, "b": False}
    result = exact_mcnemar(same, dict(same))
    assert result["fixed"] == 0
    assert result["broken"] == 0
    assert result["p_value"] == 1.0


def test_compare_antisymmetric_inference_reports_delta_and_mcnemar():
    from vrf.repair_evaluation import compare_antisymmetric_inference

    audit = []
    base_preds = {}
    rep_preds = {}
    for i in range(10):
        gold = "A" if i % 2 == 0 else "B"
        audit.append(_antisym_row(f"p{i}", "canonical", gold))
        audit.append(_antisym_row(f"p{i}", "side_swap", gold))
        # Baseline: weak/inconsistent signal (roughly at chance).
        base_preds[f"p{i}::canonical"] = _antisym_pred(f"p{i}", "canonical", 0.5)
        base_preds[f"p{i}::side_swap"] = _antisym_pred(f"p{i}", "side_swap", 0.5)
        # Repaired: strong content-tracking signal (always correct).
        prob_b_canonical = 0.05 if gold == "A" else 0.95
        prob_b_swap = 0.95 if gold == "A" else 0.05
        rep_preds[f"p{i}::canonical"] = _antisym_pred(f"p{i}", "canonical", prob_b_canonical)
        rep_preds[f"p{i}::side_swap"] = _antisym_pred(f"p{i}", "side_swap", prob_b_swap)

    result = compare_antisymmetric_inference(audit, base_preds, rep_preds)
    assert result["repaired_antisymmetric_accuracy"] == 1.0
    assert result["fine_tuning_delta_over_null"] > 0
    assert result["mcnemar"]["fixed"] >= result["mcnemar"]["broken"]


def test_independent_inference_accuracy_basic():
    from vrf.repair_evaluation import independent_inference_accuracy

    audit = [_antisym_row("p0", "canonical", "A"), _antisym_row("p1", "canonical", "B")]
    preds = {
        "p0::canonical": {"id": "p0::canonical", "predicted_riskier_side": "A"},
        "p1::canonical": {"id": "p1::canonical", "predicted_riskier_side": "A"},
    }
    accuracy = independent_inference_accuracy(audit, preds)
    assert accuracy == 0.5


def test_independent_inference_relation_violation_detects_swap_inconsistency():
    from vrf.repair_evaluation import independent_inference_relation_violation

    audit = [
        _antisym_row("p0", "canonical", "A"),
        _antisym_row("p0", "side_swap", "B"),
        _antisym_row("p1", "canonical", "B"),
        _antisym_row("p1", "side_swap", "A"),
    ]
    preds = {
        # p0: canonical predicts A, side_swap SHOULD predict B (equivariant) -- it does.
        "p0::canonical": {"id": "p0::canonical", "predicted_riskier_side": "A"},
        "p0::side_swap": {"id": "p0::side_swap", "predicted_riskier_side": "B"},
        # p1: canonical predicts B, side_swap predicts B too -- violates equivariance.
        "p1::canonical": {"id": "p1::canonical", "predicted_riskier_side": "B"},
        "p1::side_swap": {"id": "p1::side_swap", "predicted_riskier_side": "B"},
    }
    result = independent_inference_relation_violation(audit, preds)
    assert result["n"] == 2
    assert result["violation_rate"] == 0.5
    assert result["marginal_conditioned_violation_baseline"] is not None
    assert (
        result["marginal_conditioned_violation_baseline_method"]
        == "relation_stratified_marginal_independence"
    )

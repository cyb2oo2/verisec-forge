import pytest

from vrf.prediction_validation import prediction_index
from vrf.relational_evaluation import marginal_conditioned_violation_baseline, relation_gap_bootstrap
from vrf.relational_runtime import runtime_accounting, materialize_runtime_rows
from vrf.nuisance_transfer import render_split_view, split_view_occurrences
from vrf.relational_benchmark import CanonicalPair, CanonicalSide, swap_pair
from vrf.repair_evaluation import antisymmetric_inference_correctness


class CharTokenizer:
    is_fast = True

    def __call__(self, text, **kwargs):
        return {"input_ids": list(range(len(text))),
                "offset_mapping": [(i, i + 1) for i in range(len(text))]}


def pair():
    return CanonicalPair("test", "pair", "project", "c", "unknown", "unknown", None,
                         CanonicalSide("original-a", "x\nsame\nold\nsame\n", True),
                         CanonicalSide("original-b", "x\nsame\nnew\nsame\n", False))


def account(text, **kwargs):
    return runtime_accounting(text, tokenizer=CharTokenizer(), model_id="test", tokenizer_id="char",
                              max_length=kwargs.pop("max_length", 10000), truncation_side="right",
                              add_special_tokens=False, **kwargs)


def test_split_offsets_bind_to_source_lines_and_preserve_candidate_ids_under_swap():
    for candidate in [pair(), swap_pair(pair())]:
        text = render_split_view(candidate)
        spans = split_view_occurrences(candidate, text)
        assert [s["source_line"] for s in spans] == [3, 3]
        assert spans[0]["candidate_id"] == candidate.side_a.id
        assert spans[1]["candidate_id"] == candidate.side_b.id
        assert all(text[s["char_start"]:s["char_end"]] == s["text"] for s in spans)
        a = account(text, changed_occurrences=spans, max_length=spans[1]["char_start"])
        assert a["critical_lines_total"] == 2
        assert a["critical_lines_visible"] == 1
        assert a["critical_hunk_truncated"] is True


def test_unknown_or_unbound_visibility_fails_closed():
    with pytest.raises(ValueError, match="no changed occurrences"):
        account("only context")
    with pytest.raises(ValueError, match="renderer-supplied"):
        account(render_split_view(pair()))
    text = render_split_view(pair())
    spans = split_view_occurrences(pair(), text)
    spans[0]["text"] = "wrong"
    with pytest.raises(ValueError, match="mismatch"):
        account(text, changed_occurrences=spans)


def test_family_base_collisions_are_rejected_before_materialization():
    rows = [{"id": str(i), "base_id": "same", "expected_relation": "identity"} for i in range(2)]
    with pytest.raises(ValueError, match="duplicate identity"):
        materialize_runtime_rows(rows, tokenizer=CharTokenizer(), model_id="m", tokenizer_id="c", max_length=5)


def test_mixed_relation_null_conditions_before_averaging():
    rows = [dict(expected_relation=relation, base_prediction="A", transformed_prediction=pred,
                 base_protocol_valid=True, transformed_protocol_valid=True, relation_success=True,
                 pair_key="same") for relation, pred in [("invariant", "A"), ("equivariant_swap", "B")]]
    assert marginal_conditioned_violation_baseline(rows)["baseline_violation_rate"] == 0
    interval = relation_gap_bootstrap(rows, iterations=20)
    assert interval["gap"] == interval["ci95_low"] == interval["ci95_high"] == 0
    assert interval["pair_groups"] == 1


@pytest.mark.parametrize("rows", [
    [{"id": "x"}, {"id": "x"}], [{"id": ""}],
    [{"id": "x", "probability_a": float("nan")}],
    [{"id": "x", "probability_a": True}],
    [{"id": "x", "probability_a": .9, "probability_b": .9}],
    [{"id": "x", "model_id": "a"}, {"id": "y", "model_id": "b"}],
])
def test_invalid_prediction_index_fails(rows):
    with pytest.raises(ValueError):
        prediction_index(rows)


def test_coverage_is_exact():
    with pytest.raises(ValueError, match="coverage"):
        prediction_index([{"id": "x"}, {"id": "extra"}], ["x"])


def test_same_pair_key_in_different_sources_and_tie_abstention():
    rows, predictions = [], {}
    for source in ["one", "two"]:
        for variant, gold in [("canonical", "A"), ("side_swap", "B")]:
            row_id = f"{source}-{variant}"
            rows.append(dict(id=row_id, dataset=source, pair_key="same", audit_variant=variant, gold_riskier_side=gold))
            predictions[row_id] = {"probability_b": .5}
    result = antisymmetric_inference_correctness(rows, predictions)
    assert result["n"] == result["ties"] == 2
    assert result["accuracy"] == result["forced_coverage"] == 0


def test_mcnemar_rejects_different_populations():
    from vrf.repair_evaluation import exact_mcnemar
    with pytest.raises(ValueError, match="identical paired populations"):
        exact_mcnemar({"a": True, "b": False}, {"a": True})

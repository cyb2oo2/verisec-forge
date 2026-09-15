import pytest
from vrf.ai_annotation import input_hash, validate_annotation


def example():
    c = {"case_id": "x", "candidate_A": "a\nb", "candidate_B": "c"}
    r = {"case_id": "x", "input_sha256": input_hash("x", "a\nb", "c"), "annotation_source": "ai",
         "vulnerable_side": "A", "context_sufficient": "yes", "confidence": "medium", "summary": "Example only",
         "evidence": [{"side": "A", "start_line": 1, "end_line": 2, "reason": "fixture"}],
         "trigger_conditions": [], "missing_context": [], "alternative_explanation": "fixture"}
    return c, r


def test_provisional_not_human():
    c, r = example()
    assert validate_annotation(r, c)["eligible_for_provisional_ab"]
    r["annotation_source"] = "human"
    with pytest.raises(ValueError):
        validate_annotation(r, c)


@pytest.mark.parametrize("change", ["hash", "line", "bool", "side"])
def test_reject_corrupt_evidence(change):
    c, r = example()
    if change == "hash": r["input_sha256"] = "bad"
    if change == "line": r["evidence"][0]["end_line"] = 3
    if change == "bool": r["evidence"][0]["start_line"] = True
    if change == "side": r["vulnerable_side"] = "both"
    with pytest.raises(ValueError): validate_annotation(r, c)


def test_uncertain_retained_not_forced():
    c, r = example()
    r.update(vulnerable_side="unclear", context_sufficient="no", missing_context=["caller"], evidence=[])
    assert not validate_annotation(r, c)["eligible_for_provisional_ab"]

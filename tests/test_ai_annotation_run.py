import pytest
from vrf.ai_annotation import input_hash
from vrf.ai_annotation_run import assemble_run


def fixture():
    cases = [{"case_id": "x", "candidate_A": "a", "candidate_B": "b"}]
    row = dict(case_id="x", input_sha256=input_hash("x", "a", "b"), annotation_source="ai",
               vulnerable_side="A", context_sufficient="yes", confidence="high", summary="fixture",
               evidence=[dict(side="A", start_line=1, end_line=1, reason="fixture")],
               trigger_conditions=[], missing_context=[], alternative_explanation="fixture")
    meta = dict(provider="mock", model_id="mock", model_version="mock", run_id="test",
                started_at="test", completed_at="test", annotation_source="ai", mock=True, parameters={})
    provenance = [dict(case_id="x", dataset="source", r1_reverse=True)]
    keys = [dict(id=str(i), case_id="x", task="security", order=i, prompt_sha256="fixture") for i in range(2)]
    return cases, [row], meta, provenance, keys


def test_orientation_mapping_and_mock_status():
    result = assemble_run(*fixture())
    assert result["status"] == "MOCK_ONLY"
    assert [r["gold"] for r in result["evaluation_keys"]] == ["B", "A"]


def test_missing_response_not_exclusion():
    args = list(fixture()); args[1] = []
    with pytest.raises(ValueError, match="incomplete"):
        assemble_run(*args)


def test_unresolved_retained():
    args = fixture(); args[1][0]["confidence"] = "low"
    result = assemble_run(*args)
    assert result["by_source"]["source"]["unresolved"] == 1
    assert result["evaluation_keys"] == []


def test_runtime_identity_required():
    args = fixture(); args[2]["model_id"] = None
    with pytest.raises(ValueError, match="model_id"):
        assemble_run(*args)

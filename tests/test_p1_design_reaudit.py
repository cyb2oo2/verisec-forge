import pytest
from scripts.audit_p1_design import header_only_answer
from vrf.ai_annotation_run import assemble_run
from tests.test_ai_annotation_run import fixture


def test_header_control_needs_no_code():
    text = "Candidate A [tag K7] (0 characters):\n\nCandidate B [tag M2] (0 characters):\n"
    assert header_only_answer(text, "K7") == "A"
    assert header_only_answer(text, "M2") == "B"


def test_context_assessment_cannot_claim_independent_execution():
    args = fixture()
    args[2].update(execution_mode="current_assistant_context", independent_contexts=True,
                   prepared_requests_executed_verbatim=False)
    with pytest.raises(ValueError, match="non-independent"):
        assemble_run(*args)


def test_context_assessment_has_distinct_status():
    args = fixture()
    args[2].update(execution_mode="current_assistant_context", independent_contexts=False,
                   prepared_requests_executed_verbatim=False, mock=False)
    assert assemble_run(*args)["status"] == "AI_EXPLORATORY_ANNOTATIONS_ACCEPTED"

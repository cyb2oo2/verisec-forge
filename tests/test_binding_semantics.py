import pytest

from vrf.binding_semantics import build_case, select_candidates, validate_design
from vrf.relational_benchmark import CanonicalPair, CanonicalSide


def pair(key="p", project="repo", code="x"):
    return CanonicalPair("source", key, project, "c", "", "", None,
                         CanonicalSide("a", code + " unsafe", True),
                         CanonicalSide("b", code + " fixed", False))


def test_factorial_preserves_code_and_balances_answers():
    p = pair(code="literal ```\nCandidate A")
    prompts, keys, _ = build_case(p)
    assert validate_design(prompts, keys) == {"status": "ok", "cases": 1, "prompts": 12}
    assert all(p.side_a.code in r["text"] and p.side_b.code in r["text"] for r in prompts)
    for task in ("security", "binding_K7", "binding_M2"):
        answers = [k["gold"] for k in keys if k["task"] == task]
        assert answers.count("A") == answers.count("B") == 2


def test_exclusion_alias_content_and_unknown():
    prior = [pair()]
    pool = [pair("q", "https://github.com/org/repo.git", "new"),
            pair("r", "other", " x "), pair("s", "unknown", "new2"),
            pair("t", "clean", "new3")]
    selected, audit = select_candidates(pool, prior)
    assert [p.pair_key for p in selected] == ["t"]
    assert audit["training_overlap"] == "not_checked"


def test_reject_corruption_and_metadata():
    prompts, keys, _ = build_case(pair())
    with pytest.raises(ValueError, match="coverage"):
        validate_design(prompts[:-1], keys)
    prompts[0]["gold"] = "A"
    with pytest.raises(ValueError, match="metadata"):
        validate_design(prompts, keys)


def test_reject_wrong_label():
    prompts, keys, _ = build_case(pair())
    keys[0]["gold"] = "B"
    with pytest.raises(ValueError):
        validate_design(prompts, keys)


def test_duplicate_pool_identity_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        select_candidates([pair(), pair()], [])

"""Tests for the agent skill catalog validator.

Skill files are agent-facing instructions: whatever they model, an agent will
reproduce. These tests assert the validator's behaviour on synthetic inputs, and
then that the real catalog satisfies it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from scripts.check_skill_catalog import check, parse_frontmatter  # noqa: E402

SKILLS = ROOT / ".github" / "skills"


# ---------------------------------------------------------------------------
# Frontmatter must be the first bytes
# ---------------------------------------------------------------------------


def test_frontmatter_must_be_the_first_bytes() -> None:
    banner_first = (
        "> **HISTORICAL NOTE.**\n> Something.\n\n---\nname: x\ndescription: y\n---\n\nBody\n"
    )
    mapping, error = parse_frontmatter(banner_first)
    assert mapping is None
    assert "content precedes frontmatter" in error


def test_valid_frontmatter_parses_and_notice_may_follow() -> None:
    text = "---\nname: x\ndescription: y\n---\n\n> **NOTICE.** After the delimiter.\n\nBody\n"
    mapping, error = parse_frontmatter(text)
    assert error == ""
    assert mapping == {"name": "x", "description": "y"}


def test_unterminated_frontmatter_is_rejected() -> None:
    mapping, error = parse_frontmatter("---\nname: x\n\nBody with no closing delimiter\n")
    assert mapping is None
    assert "no matching close" in error


@pytest.mark.skipif(not SKILLS.exists(), reason="skill catalog not on this branch")
def test_every_skill_file_starts_with_valid_frontmatter() -> None:
    failures = []
    for skill in sorted(SKILLS.rglob("SKILL.md")):
        mapping, error = parse_frontmatter(skill.read_text(encoding="utf-8"))
        if mapping is None:
            failures.append(f"{skill.relative_to(ROOT)}: {error}")
        elif "name" not in mapping or "description" not in mapping:
            failures.append(f"{skill.relative_to(ROOT)}: missing name/description")
    assert not failures, "invalid skill frontmatter:\n" + "\n".join(failures)


# ---------------------------------------------------------------------------
# The catalog as a whole
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SKILLS.exists(), reason="skill catalog not on this branch")
def test_skill_catalog_has_no_violations() -> None:
    problems = check()
    assert problems == [], "skill catalog problems:\n" + "\n".join(
        f"  {p['file']}:{p['line']} [{p['kind']}] {p['detail']}" for p in problems[:20]
    )


@pytest.mark.skipif(not SKILLS.exists(), reason="skill catalog not on this branch")
def test_no_withdrawn_value_appears_as_an_active_worked_example() -> None:
    """A banner is not enough: the body must not teach the withdrawn numbers."""

    problems = [p for p in check() if p["kind"] == "withdrawn_value_in_active_example"]
    assert problems == [], (
        "withdrawn values still used as active worked examples:\n"
        + "\n".join(f"  {p['file']}:{p['line']} {p['detail']}" for p in problems)
    )


@pytest.mark.skipif(not SKILLS.exists(), reason="skill catalog not on this branch")
def test_catalog_links_resolve_to_tracked_files() -> None:
    problems = [p for p in check() if p["kind"] in {"broken_link", "link_escapes_repository"}]
    assert problems == [], "broken catalog links:\n" + "\n".join(
        f"  {p['file']}:{p['line']} {p['detail']}" for p in problems
    )


@pytest.mark.skipif(not SKILLS.exists(), reason="skill catalog not on this branch")
def test_catalog_contains_no_local_or_private_paths() -> None:
    problems = [p for p in check() if p["kind"] in {"local_path", "private_reference"}]
    assert problems == [], "private/local references in catalog:\n" + "\n".join(
        f"  {p['file']}:{p['line']} {p['detail']}" for p in problems
    )


@pytest.mark.skipif(not SKILLS.exists(), reason="skill catalog not on this branch")
def test_catalog_claim_examples_agree_with_the_ledger() -> None:
    problems = [p for p in check() if p["kind"] in {"ledger_disagreement", "missing_dependency_document"}]
    assert problems == [], "catalog disagrees with the result status ledger:\n" + "\n".join(
        f"  {p['file']} {p['detail']}" for p in problems
    )


@pytest.mark.skipif(not SKILLS.exists(), reason="skill catalog not on this branch")
def test_mandatory_strongest_control_is_stated_in_research_skills() -> None:
    """The two research-facing skills must require the strongest control."""

    for relative in (
        "research-experiment-manager/SKILL.md",
        "scientific-paper-assistant/SKILL.md",
    ):
        text = (SKILLS / relative).read_text(encoding="utf-8").lower()
        assert "strongest semantics-free" in text, (
            f"{relative} does not require the strongest semantics-free structural control"
        )
        assert "cannot test diff structure" in text or "no semantic advantage" in text, (
            f"{relative} does not state the current conclusion"
        )

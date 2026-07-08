"""Checks for the external review packet: docs/EXTERNAL_REVIEW_REQUEST.md and
docs/EXTERNAL_REVIEW_EMAIL_TEMPLATE.md exist, are indexed, carry working-draft
framing and the main claim boundary, avoid forbidden bare overclaims, resolve
every referenced path, and introduce no new [RESULT: ...] anchors.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUEST_PATH = ROOT / "docs/EXTERNAL_REVIEW_REQUEST.md"
EMAIL_PATH = ROOT / "docs/EXTERNAL_REVIEW_EMAIL_TEMPLATE.md"

# The six forbidden overclaims named in the task brief, checked as literal
# (case-insensitive) substrings. Legitimate disclaimers are written with
# different word order/phrasing so they never trip this check -- e.g. "does
# not solve secure patch reasoning" instead of "solved secure patch
# reasoning", "deployed vulnerability scanner" instead of "...detector".
FORBIDDEN_PHRASES = [
    "solved secure patch reasoning",
    "universal model failure",
    "internal mechanism proof",
    "validated learned repair",
    "deployed vulnerability detector",
    "top-conference-ready",
]


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_both_docs_exist_and_are_indexed():
    assert REQUEST_PATH.exists()
    assert EMAIL_PATH.exists()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "reports/RESULTS_INDEX.md").read_text(encoding="utf-8")
    for doc in ("docs/EXTERNAL_REVIEW_REQUEST.md", "docs/EXTERNAL_REVIEW_EMAIL_TEMPLATE.md"):
        assert doc in readme, doc
        assert doc in index, doc


def test_both_docs_state_working_draft_framing():
    for path in (REQUEST_PATH, EMAIL_PATH):
        assert "working draft" in _text(path).lower(), path


def test_both_docs_state_the_main_claim_boundary():
    for path in (REQUEST_PATH, EMAIL_PATH):
        normalized = _text(path).lower()
        assert "pointwise" in normalized, path


def test_request_covers_required_sections():
    text = _text(REQUEST_PATH)
    for heading in [
        "## Project Summary",
        "## What To Read First",
        "## What Feedback Is Being Requested",
        "## What This Work Does Not Claim",
        "## Known Limitations",
        "## Links",
    ]:
        assert heading in text, heading


def test_email_template_has_both_versions():
    text = _text(EMAIL_PATH)
    assert "## Version A: Supervisor / Collaborator" in text
    assert "## Version B: Cold PI / PhD Advisor Outreach" in text


def test_no_forbidden_overclaims_present():
    for path in (REQUEST_PATH, EMAIL_PATH):
        normalized = _text(path).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in normalized, f"{path}: found forbidden phrase '{phrase}'"


def test_no_new_result_anchors_introduced():
    for path in (REQUEST_PATH, EMAIL_PATH):
        assert "[RESULT:" not in _text(path), path


def test_referenced_paths_resolve():
    text = _text(REQUEST_PATH)
    dir_pat = re.compile(
        r"`((?:reports|docs|paper|src|scripts|reproducibility)/[A-Za-z0-9_./-]+\.(?:md|json|py|svg))`"
    )
    for rel in set(dir_pat.findall(text)):
        assert (ROOT / rel).exists(), rel

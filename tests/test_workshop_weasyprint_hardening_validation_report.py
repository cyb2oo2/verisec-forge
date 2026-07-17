"""Checks for paper/workshop_weasyprint_hardening_validation_report.md: the
report exists, records the before-test environment state, records
--check-only and full-build output, states whether the PR #82 hardening
fixed the --check-only crash, states whether a PDF was produced, states no
page fit or SaTML formatting was claimed, recommends exactly one next PR,
adds no new [RESULT: ...] anchors, and avoids forbidden overclaims.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "paper/workshop_weasyprint_hardening_validation_report.md"

FORBIDDEN_PHRASES = [
    "solved secure patch reasoning",
    "universal model failure",
    "internal mechanism proof",
    "validated learned repair",
    "deployed vulnerability detector",
    "top-conference-ready",
]


def _text() -> str:
    return REPORT_PATH.read_text(encoding="utf-8")


def _normalized_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("*", ""))


def test_report_exists_and_is_nonempty() -> None:
    assert REPORT_PATH.exists()
    assert _text().strip()


def test_records_before_test_environment_state() -> None:
    section = _text().split("## 2. Environment State Before Test")[1].split("## 3.")[0]
    normalized = section.lower()
    assert "not importable" in normalized
    assert "modulenotfounderror" in normalized
    assert "pyproject.toml" in normalized


def test_records_check_only_and_full_build_output() -> None:
    section = _text().split("## 3. Commands Run and Recorded Output")[1].split("## 4.")[0]
    normalized = section.lower()
    assert "check-only" in normalized
    assert "full build" in normalized
    assert "exit code" in normalized


def test_states_whether_hardening_fixed_the_crash() -> None:
    section = _text().split("## 4. Interpretation")[1].split("## 5.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "did the hardening fix work? yes." in normalized


def test_states_whether_pdf_was_produced() -> None:
    section = _text().split("## 4. Interpretation")[1].split("## 5.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "was a pdf produced? no." in normalized


def test_does_not_claim_page_fit_or_satml_formatting() -> None:
    section = _text().split("## 4. Interpretation")[1].split("## 5.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "was page fit or satml formatting validated? no" in normalized


def test_records_nothing_generated_was_committed() -> None:
    section = _text().split("## 3. Commands Run and Recorded Output")[1].split("## 4.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "whether anything generated was committed: no" in normalized


def test_recommends_exactly_one_next_pr() -> None:
    text = _text()
    section = text.split("## 5. Recommended Next PR")[1]
    recommended = re.findall(r"\*\*Recommendation: `([^`]+)`", section, flags=re.DOTALL)
    assert len(recommended) == 1, recommended
    normalized = _normalized_whitespace(recommended[0])
    assert normalized == "paper: attempt MSYS2 native-library install for weasyprint"


def test_introduces_no_new_result_anchors() -> None:
    text = _text()
    draft_anchors = set(
        re.findall(
            r"\[RESULT: [a-z0-9-]+\]",
            (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8"),
        )
    )
    report_anchors = set(re.findall(r"\[RESULT: [a-z0-9-]+\]", text))
    assert report_anchors <= draft_anchors


def test_has_no_forbidden_overclaims() -> None:
    normalized = _text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in normalized, f"found forbidden phrase: {phrase!r}"

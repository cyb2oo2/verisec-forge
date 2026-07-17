"""Checks for paper/workshop_weasyprint_validation_report.md: the report
exists, records the install attempt and the build attempt, states whether
a PDF was produced, states the generated PDF was not committed, states no
page fit was claimed, states SaTML formatting was not validated,
recommends exactly one next PR, adds no new [RESULT: ...] anchors, and
avoids forbidden overclaims.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "paper/workshop_weasyprint_validation_report.md"

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


def test_install_attempt_is_recorded() -> None:
    section = _text().split("## 2. Install Attempt")[1].split("## 3.")[0]
    normalized = section.lower()
    assert "pip install markdown weasyprint" in normalized
    assert "dependency file" in normalized


def test_build_attempt_is_recorded() -> None:
    section = _text().split("## 3. Build Attempt")[1].split("## 4.")[0]
    normalized = section.lower()
    assert "check-only" in normalized
    assert "exit code" in normalized
    assert "full build" in normalized


def test_report_states_whether_pdf_was_produced() -> None:
    section = _text().split("## 3. Build Attempt")[1].split("## 4.")[0]
    normalized = section.lower()
    assert "whether a pdf was produced" in normalized


def test_report_states_generated_pdf_not_committed() -> None:
    section = _text().split("## 3. Build Attempt")[1].split("## 4.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "whether any generated artifact was committed: no" in normalized


def test_report_does_not_claim_page_fit() -> None:
    section = _text().split("## 4. Interpretation")[1].split("## 5.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "was page fit validated? no" in normalized


def test_report_states_satml_formatting_not_validated() -> None:
    section = _text().split("## 4. Interpretation")[1].split("## 5.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "was satml formatting validated? no" in normalized


def test_report_recommends_exactly_one_next_pr() -> None:
    text = _text()
    section = text.split("## 5. Recommended Next PR")[1]
    recommended = re.findall(r"\*\*Recommendation: `([^`]+)`", section, flags=re.DOTALL)
    assert len(recommended) == 1, recommended
    normalized = _normalized_whitespace(recommended[0])
    assert normalized == "paper: harden weasyprint install instructions"


def test_report_introduces_no_new_result_anchors() -> None:
    text = _text()
    draft_anchors = set(
        re.findall(
            r"\[RESULT: [a-z0-9-]+\]",
            (ROOT / "paper/draft_v0.md").read_text(encoding="utf-8"),
        )
    )
    report_anchors = set(re.findall(r"\[RESULT: [a-z0-9-]+\]", text))
    assert report_anchors <= draft_anchors


def test_report_has_no_forbidden_overclaims() -> None:
    normalized = _text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in normalized, f"found forbidden phrase: {phrase!r}"

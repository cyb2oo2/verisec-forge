"""Checks for paper/workshop_build_smoke_report.md: the report exists,
mentions both build commands, records check-only and full-build behavior,
does not claim page fit, does not require a committed generated PDF,
recommends exactly one next action, adds no new [RESULT: ...] anchors, and
avoids forbidden overclaims.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "paper/workshop_build_smoke_report.md"

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
    return re.sub(r"\s+", " ", text)


def test_report_exists_and_is_nonempty() -> None:
    assert REPORT_PATH.exists()
    assert _text().strip()


def test_report_mentions_both_commands() -> None:
    text = _text()
    assert "build_workshop_draft_pdf.py --check-only" in text
    assert "build_workshop_draft_pdf.py" in text


def test_report_records_check_only_behavior() -> None:
    section = _text().split("## 3. Observed Behavior")[1].split("## 4.")[0]
    normalized = section.lower()
    assert "check-only" in normalized
    assert "exit code" in normalized
    assert "pandoc" in normalized


def test_report_records_full_build_behavior() -> None:
    section = _text().split("## 3. Observed Behavior")[1].split("## 4.")[0]
    normalized = section.lower()
    assert "full build" in normalized
    assert "failed" in normalized


def test_report_does_not_claim_page_fit() -> None:
    normalized = _normalized_whitespace(_text()).lower()
    assert "no page fit is validated" in normalized
    assert "confirmed page fit" not in normalized
    assert "validated page fit" not in normalized


def test_report_does_not_require_committed_pdf() -> None:
    normalized = _normalized_whitespace(_text()).lower()
    assert "no generated artifact should be committed" in normalized


def test_report_recommends_exactly_one_next_action() -> None:
    text = _text()
    section = text.split("## 5. Next Action")[1]
    recommended = re.findall(r"\*\*Recommendation: `([^`]+)`", section, flags=re.DOTALL)
    assert len(recommended) == 1, recommended
    normalized = _normalized_whitespace(recommended[0])
    assert normalized == "paper: install or document one supported PDF toolchain"


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

"""Checks for paper/workshop_weasyprint_msys2_install_report.md: the
report exists, records the pre-install baseline, records the native-library
install attempt, records post-install validation, states whether a PDF was
produced, states generated PDFs were not committed, states no page fit or
SaTML formatting was claimed, recommends exactly one next PR, adds no new
[RESULT: ...] anchors, and avoids forbidden overclaims.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "paper/workshop_weasyprint_msys2_install_report.md"

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


def test_records_baseline_before_install() -> None:
    section = _text().split("## 2. Baseline Before Install")[1].split("## 3.")[0]
    normalized = section.lower()
    assert "modulenotfounderror" in normalized
    assert "check-only" in normalized
    assert "exit code" in normalized


def test_records_native_library_install_attempt() -> None:
    section = _text().split("## 3. Native-Library Install Attempt")[1].split("## 4.")[0]
    normalized = section.lower()
    assert "pacman" in normalized
    assert "msys2" in normalized
    assert "whether msys2 was available" in normalized
    assert "whether `pacman` was available" in normalized
    assert "exact blocker" in normalized


def test_records_post_install_validation() -> None:
    section = _text().split("## 4. Post-Install Validation")[1].split("## 5.")[0]
    normalized = section.lower()
    assert "import result" in normalized
    assert "weasyprint --info" in normalized
    assert "check-only" in normalized
    assert "full build result" in normalized


def test_states_whether_pdf_was_produced() -> None:
    section = _text().split("## 4. Post-Install Validation")[1].split("## 5.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "whether `build/workshop_draft_v1.pdf` was produced: no" in normalized


def test_states_generated_pdfs_not_committed() -> None:
    section = _text().split("## 4. Post-Install Validation")[1].split("## 5.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "whether any generated pdf was committed: no" in normalized


def test_does_not_claim_page_fit() -> None:
    section = _text().split("## 5. Interpretation")[1].split("## 6.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "was page fit validated? no" in normalized


def test_does_not_claim_satml_formatting() -> None:
    section = _text().split("## 5. Interpretation")[1].split("## 6.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "was satml formatting validated? no" in normalized


def test_recommends_exactly_one_next_pr() -> None:
    text = _text()
    section = text.split("## 6. Recommended Next PR")[1]
    recommended = re.findall(r"\*\*Recommendation: `([^`]+)`", section, flags=re.DOTALL)
    assert len(recommended) == 1, recommended
    normalized = _normalized_whitespace(recommended[0])
    assert normalized == "paper: document unavailable MSYS2 install path"


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

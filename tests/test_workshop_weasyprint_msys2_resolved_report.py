"""Checks for paper/workshop_weasyprint_msys2_resolved_report.md: the
report exists, records the native-library install that was run, records
post-install validation, states the libgobject-2.0-0 blocker was
resolved, states a PDF was produced, states the generated PDF was not
committed, states no page fit or SaTML formatting was claimed,
recommends exactly one next PR, adds no new [RESULT: ...] anchors, and
avoids forbidden overclaims.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "paper/workshop_weasyprint_msys2_resolved_report.md"

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


def test_records_native_library_install() -> None:
    section = _text().split("## 3. Native-Library Install")[1].split("## 4.")[0]
    normalized = section.lower()
    assert "pacman.exe -s --noconfirm mingw-w64-x86_64-pango" in normalized
    assert "succeeded" in normalized
    assert "libgobject-2.0-0.dll" in normalized


def test_records_post_install_validation() -> None:
    section = _text().split("## 4. Post-Install Validation")[1].split("## 5.")[0]
    normalized = section.lower()
    assert "import result" in normalized
    assert "weasyprint --info" in normalized
    assert "check-only" in normalized
    assert "full build result" in normalized


def test_states_libgobject_blocker_resolved() -> None:
    section = _text().split("## 5. Interpretation")[1].split("## 6.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "did msys2/pango resolve the `libgobject-2.0-0` blocker? yes." in normalized


def test_states_pdf_was_produced() -> None:
    section = _text().split("## 4. Post-Install Validation")[1].split("## 5.")[0]
    normalized = _normalized_whitespace(section).lower()
    assert "whether `build/workshop_draft_v1.pdf` was produced: yes" in normalized


def test_states_generated_pdf_not_committed() -> None:
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
    assert normalized == "paper: add rendered PDF inspection checklist"


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

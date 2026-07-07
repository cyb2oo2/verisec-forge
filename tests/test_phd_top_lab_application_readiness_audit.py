"""Checks for docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md: it exists, is
indexed, covers all eleven required sections, states the 1-5 score scale,
chooses exactly one recommended next move, and keeps its application-facing
wording free of forbidden overclaims.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = ROOT / "docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md"

REQUIRED_SECTION_HEADINGS = [
    "## 1. Overall verdict",
    "## 2. What signal this project sends",
    "## 3. What signal it does not yet send",
    "## 4. Comparison against typical PhD applicant projects",
    "## 5. How to present it in applications",
    "## 6. Whether to apply now",
    "## 7. Missing pieces for top-lab exceptional signal",
    "## 8. Application strategy",
    "## 9. Risk audit",
    "## 10. Recommended next move",
    "## 11. Final blunt verdict",
]

# The 1-5 scale labels required by the task brief.
REQUIRED_SCALE_LABELS = [
    "ordinary class project",
    "solid engineering project",
    "credible research artifact",
    "strong independent research signal",
    "unusually strong top-lab signal",
]

# Forbidden overclaim phrases the application wording (Section 5) must avoid.
FORBIDDEN_PHRASES = [
    "solved secure patch reasoning",
    "universal model failure",
    "internal mechanism proof",
    "validated learned repair",
    "deployed vulnerability detection",
    "all models fail",
    "proves a shared internal mechanism",
]

# Exactly one of these next-move letters may be chosen as "Recommended: X".
NEXT_MOVE_LETTERS = ["A", "B", "C", "D", "E", "F"]


def _text() -> str:
    return AUDIT_PATH.read_text(encoding="utf-8")


def _normalized(text: str) -> str:
    return " ".join(text.split()).lower()


def test_audit_exists_and_is_indexed():
    assert AUDIT_PATH.exists()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "reports/RESULTS_INDEX.md").read_text(encoding="utf-8")
    assert "docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md" in readme
    assert "docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md" in index


def test_audit_covers_all_eleven_sections():
    text = _text()
    for heading in REQUIRED_SECTION_HEADINGS:
        assert heading in text, heading


def test_audit_states_the_1_to_5_score_scale():
    normalized = _normalized(_text())
    for label in REQUIRED_SCALE_LABELS:
        assert label in normalized, label


def test_audit_gives_current_and_realistic_score():
    normalized = _normalized(_text())
    assert "score:" in normalized
    assert "realistic score after one more preparation step" in normalized


def test_audit_chooses_exactly_one_next_move():
    text = _text()
    matches = re.findall(r"\*\*Recommended:\s*([A-F])\b", text)
    assert len(matches) == 1, f"expected exactly one recommended next move, found {matches}"
    assert matches[0] in NEXT_MOVE_LETTERS


def test_audit_specifies_next_pr_title_and_scope():
    normalized = _normalized(_text())
    assert "best next pr title" in normalized
    assert "exact scope" in normalized
    assert "what not to do" in normalized


def test_application_wording_avoids_forbidden_overclaims():
    # Restrict to Section 5 (the actual application-facing wording): the rest
    # of the audit legitimately discusses these phrases in bounded/negated
    # form (e.g. "not a validated learned repair") as claim-boundary language.
    text = _text()
    # Skip the section's own meta sentence describing what to avoid (it names
    # the forbidden phrases directly as instructions, not as applied wording).
    start = text.index("**CV (1 sentence):**")
    end = text.index("## 6. Whether to apply now")
    section5 = text[start:end].lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in section5, f"found forbidden overclaim phrase in Section 5: '{phrase}'"


def test_referenced_paths_resolve():
    text = _text()
    dir_pat = re.compile(
        r"`((?:reports|docs|paper|src|scripts|reproducibility|application_materials)/[A-Za-z0-9_./-]+\.(?:md|json|py))`"
    )
    for rel in set(dir_pat.findall(text)):
        assert (ROOT / rel).exists(), rel
    bare_pat = re.compile(r"`([A-Z][A-Z0-9_]+\.md)`")
    for name in set(bare_pat.findall(text)):
        assert (ROOT / "reports" / name).exists() or (ROOT / name).exists(), name

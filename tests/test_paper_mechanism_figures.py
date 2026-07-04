"""Checks for the new mechanism/confound/repair figures (Figures 5-7): the SVG
files exist and are well-formed, the draft references each with its required
caption caveat, the generator is deterministic and sources only committed
report artifacts, and no new [RESULT: ...] anchor was silently introduced.
"""

from __future__ import annotations

import re
import subprocess
import sys
import xml.dom.minidom
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DRAFT_PATH = ROOT / "paper/draft_v0.md"
FIG_DIR = ROOT / "paper/figures"
GENERATOR = ROOT / "scripts/build_paper_mechanism_figures.py"

NEW_FIGURES = {
    "figure5_label_polarity_mechanism.svg": (
        "figures/figure5_label_polarity_mechanism.svg",
        "does not establish a shared internal mechanism",
    ),
    "figure6_crossvul_confound.svg": (
        "figures/figure6_crossvul_confound.svg",
        "not standalone evidence of stronger secure-code reasoning",
    ),
    "figure7_repair_decomposition.svg": (
        "figures/figure7_repair_decomposition.svg",
        "learned fine-tuning repair is not\nvalidated as transferable repair",
    ),
}


def _normalized(text: str) -> str:
    return " ".join(text.split()).lower()


def test_new_figure_files_exist_and_are_valid_svg():
    for name in NEW_FIGURES:
        path = FIG_DIR / name
        assert path.exists(), name
        text = path.read_text(encoding="utf-8")
        assert text.startswith("<svg"), name
        assert "</svg>" in text, name
        xml.dom.minidom.parseString(text)  # raises if not well-formed


def test_draft_references_each_new_figure_with_caption_caveat():
    draft = DRAFT_PATH.read_text(encoding="utf-8")
    normalized = _normalized(draft)
    for _name, (ref, caveat) in NEW_FIGURES.items():
        assert ref in draft, ref
        assert _normalized(caveat) in normalized, caveat


def test_draft_has_figures_5_6_7_captions():
    normalized = _normalized(DRAFT_PATH.read_text(encoding="utf-8"))
    for n in ("figure 5.", "figure 6.", "figure 7."):
        assert n in normalized, n


def test_generator_is_deterministic_and_sources_committed_artifacts():
    # Sources only reports/*.json (committed); no model run, no randomness.
    src = GENERATOR.read_text(encoding="utf-8")
    assert "reports/" in src
    # Non-deterministic code usages (not prose): imports/calls, not the word
    # "randomness" in the docstring.
    for banned in ("import random", "random.", "Math.random", "datetime.now", "time.time("):
        assert banned not in src, banned
    # Re-running produces byte-identical files.
    before = {n: (FIG_DIR / n).read_text(encoding="utf-8") for n in NEW_FIGURES}
    result = subprocess.run(
        [sys.executable, str(GENERATOR)], capture_output=True, text=True, cwd=str(ROOT)
    )
    assert result.returncode == 0, result.stderr
    for n in NEW_FIGURES:
        assert (FIG_DIR / n).read_text(encoding="utf-8") == before[n], n


def test_generator_only_reads_existing_report_paths():
    src = GENERATOR.read_text(encoding="utf-8")
    for rel in set(re.findall(r'"(reports/[A-Za-z0-9_./-]+\.json)"', src)):
        assert (ROOT / rel).exists(), rel


def test_no_new_result_anchor_introduced_by_figures():
    # Figures reuse the reports behind Tables 2-4; the draft anchor set must
    # still equal the anchor-map set (no orphan figure anchors).
    draft = DRAFT_PATH.read_text(encoding="utf-8")
    anchor_map = (ROOT / "paper/result_anchor_map.md").read_text(encoding="utf-8")
    pattern = re.compile(r"\[RESULT: [a-z0-9-]+\]")
    assert set(pattern.findall(draft)) == set(pattern.findall(anchor_map))

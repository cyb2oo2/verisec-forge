"""Checks for the CrossVul polarity/gold confound artifacts: report is
indexed, JSON is well-formed, cited paths resolve, and no claim overreaches
into a model-quality assertion the analysis doesn't support (this is a
dataset/presentation-structure analysis, not evidence the model "generalizes
better/worse" or that CrossVul accuracy is "fake").
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "reports/CROSSVUL_POLARITY_GOLD_CONFOUND.md"
JSON_PATH = ROOT / "reports/crossvul_polarity_gold_confound_v1.json"

FORBIDDEN_PHRASES = [
    "crossvul accuracy is fake",
    "model generalizes better",
    "model generalizes worse",
]


def _strip_quoted_spans(text: str) -> str:
    return re.sub(r'"[^"]*"', "", text)


def test_report_exists_and_is_indexed():
    assert REPORT_PATH.exists()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    results_index = (ROOT / "reports/RESULTS_INDEX.md").read_text(encoding="utf-8")
    assert "reports/CROSSVUL_POLARITY_GOLD_CONFOUND.md" in readme
    assert "reports/CROSSVUL_POLARITY_GOLD_CONFOUND.md" in results_index


def test_report_has_dataset_analysis_claim_boundary():
    text = REPORT_PATH.read_text(encoding="utf-8")
    normalized = " ".join(text.split()).lower()
    assert "dataset/presentation-structure analysis, not a model-quality claim" in normalized
    unquoted = _strip_quoted_spans(text).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in unquoted, f"found unquoted '{phrase}' in report"


def test_report_states_the_stronger_confound_finding_with_caution():
    text = REPORT_PATH.read_text(encoding="utf-8")
    normalized = " ".join(text.split()).lower()
    # The measured result (stronger CrossVul confound) uses the preferred
    # wording, not an overclaim.
    assert (
        "should not be read as stronger secure-code reasoning by itself" in normalized
    )
    assert "consistent with, though this analysis alone does not prove" in normalized


def test_json_artifact_is_well_formed_and_matches_report_numbers():
    assert JSON_PATH.exists()
    payload = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert payload["status"] == "ok"
    assert payload["scope"] == "crossvul_polarity_gold_confound"
    assert "claim_boundary" in payload

    canonical = payload["eval"]["by_variant"]["canonical"]["polarity_gold_correlation"]
    assert round(canonical["shortcut_accuracy"], 3) == 0.855

    polarity_only = payload["eval"]["by_variant"]["polarity_only_swap"][
        "polarity_gold_correlation"
    ]
    assert round(polarity_only["shortcut_accuracy"], 3) == 0.151

    agreement = payload["eval"]["by_variant"]["canonical"]["model_vs_shortcut"]
    assert agreement is not None
    assert round(agreement["agreement"], 2) == 0.92

    cleanliness = payload["source"]["pair_cleanliness"]
    assert cleanliness["dirty_pair_groups"] == 0
    assert cleanliness["clean_one_vulnerable_one_secure_pairs"] == cleanliness["total_pair_keys"]


def test_report_referenced_paths_resolve():
    text = REPORT_PATH.read_text(encoding="utf-8")
    pattern = re.compile(r"`((?:reports|docs|src|scripts)/[A-Za-z0-9_./-]+\.(?:md|json|py))`")
    for relative_path in set(pattern.findall(text)):
        assert (ROOT / relative_path).exists(), relative_path


def test_experiment_completeness_audit_marks_confound_resolved():
    audit = (ROOT / "docs/EXPERIMENT_COMPLETENESS_AUDIT.md").read_text(encoding="utf-8")
    normalized = " ".join(audit.split()).lower()
    assert "reports/crossvul_polarity_gold_confound.md" in normalized
    assert "codebert label/polarity mechanism replication" in normalized

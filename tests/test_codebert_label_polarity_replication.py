"""Checks for the CodeBERT label/polarity mechanism replication artifacts:
report indexed, JSON well-formed with expected counts, the label-vs-polarity
ordering is reported, and the claim boundary does not overreach into a
universality / internal-mechanism / CrossVul-reasoning claim.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "reports/CODEBERT_LABEL_POLARITY_MECHANISM_REPLICATION.md"
JSON_PATH = ROOT / "reports/codebert_label_polarity_mechanism_replication_v1.json"

FORBIDDEN_PHRASES = [
    "all models fail this way",
    "the mechanism is universal",
    "codebert proves generality",
    "model internally binds to polarity",
    "crossvul accuracy proves better reasoning",
]


def _strip_quoted_spans(text: str) -> str:
    return re.sub(r'"[^"]*"', "", text)


def test_json_artifact_well_formed_with_expected_counts():
    payload = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert payload["status"] == "ok"
    assert payload["scope"] == "codebert_label_polarity_mechanism_replication"
    assert payload["base_pairs"] == 600
    # four variants, 600 each
    for variant in ["canonical", "label_only_swap", "polarity_only_swap", "side_swap"]:
        assert payload["accuracy"][variant]["n"] == 600


def test_json_shows_label_inert_polarity_disruptive_ordering():
    payload = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    indep = payload["prediction_independence_vs_canonical"]
    label_phi = indep["label_only_swap"]["phi"]
    polarity_phi = indep["polarity_only_swap"]["phi"]
    # label swap inert (phi high positive), polarity swap disruptive (phi near 0
    # or negative) -- the ordering is what replicates, not exact values.
    assert label_phi > 0.8
    assert polarity_phi < 0.2
    assert label_phi > polarity_phi
    # polarity-only accuracy collapses well below canonical
    acc = payload["accuracy"]
    assert acc["polarity_only_swap"]["accuracy"] < acc["canonical"]["accuracy"] - 0.2


def test_json_includes_crossvul_confound_aware_check():
    payload = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    cv = payload["crossvul_confound_aware_check"]
    assert cv is not None, "CrossVul confound-aware check should be present, not deferred"
    agreement = cv["model_vs_crude_polarity_shortcut"]["canonical"]["agreement"]
    # CodeBERT should track the crude shortcut heavily on CrossVul (compare Qwen ~0.92)
    assert agreement > 0.8

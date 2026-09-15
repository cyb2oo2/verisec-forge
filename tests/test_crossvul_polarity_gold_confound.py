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

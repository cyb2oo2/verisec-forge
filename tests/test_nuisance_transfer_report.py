"""Checks for the held-out nuisance-transform transfer artifacts.

These target the small committed report JSONs (reports/ is not gitignored),
not the large processed datasets or GPU prediction outputs (both gitignored),
so they run in a fresh clone / CI without GPU access.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from vrf.nuisance_transfer import NUISANCE_FAMILIES

ROOT = Path(__file__).resolve().parents[1]


def test_nuisance_families_list_has_five_distinct_entries():
    assert len(NUISANCE_FAMILIES) == 5
    assert len(set(NUISANCE_FAMILIES)) == 5


def test_dataset_build_summary_reports_expected_row_counts():
    summary_path = ROOT / "reports/secure_code_nuisance_transfer_audit_dataset_v1.json"
    assert summary_path.exists(), summary_path
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["status"] == "ok"
    assert summary["base_pairs"] == 600
    # 600 base pairs x 5 families x 2 variants (canonical, side_swap).
    assert summary["rows"] == 600 * len(NUISANCE_FAMILIES) * 2
    assert summary["build_errors"] == []
    assert set(summary["nuisance_families"]) == set(NUISANCE_FAMILIES)


def test_decomposition_json_is_well_formed_with_all_families():
    result_path = ROOT / "reports/secure_code_repair_antisymmetric_nuisance_transfer_v1.json"
    assert result_path.exists(), result_path
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result["status"] == "ok"
    assert set(result["families"]) == set(NUISANCE_FAMILIES)
    for family, entry in result["families"].items():
        assert entry["pair_count"] == 600, family
        ca = entry["canonical_accuracy"]
        for key in (
            "baseline_independent",
            "repaired_independent",
            "baseline_antisymmetric_inference_null",
            "repaired_antisymmetric_inference",
        ):
            assert 0.0 <= ca[key] <= 1.0, (family, key)
        assert "fine_tuning_delta_over_null" in entry
        mcnemar = entry["mcnemar"]
        assert mcnemar["n_pairs"] == 600, family
        assert 0.0 <= mcnemar["p_value"] <= 1.0, family


def test_decomposition_json_multiple_comparisons_block_present():
    result_path = ROOT / "reports/secure_code_repair_antisymmetric_nuisance_transfer_v1.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    mc = result["multiple_comparisons"]
    assert mc["families_tested"] == len(NUISANCE_FAMILIES)
    assert abs(mc["bonferroni_corrected_threshold"] - 0.05 / len(NUISANCE_FAMILIES)) < 1e-9
    assert "verdict" in result and result["verdict"]

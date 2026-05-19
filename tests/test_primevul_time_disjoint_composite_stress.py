from __future__ import annotations

from scripts.evaluate_primevul_time_disjoint_composite_stress import build_report


def test_composite_stress_filters_project_overlap_before_pair_coupling() -> None:
    train = [
        {"id": "train", "project": "seen", "cve": "CVE-2020-0001", "pair_key": "train-pair", "cve_year": 2020},
    ]
    eval_rows = [
        {"id": "vuln-seen", "project": "seen", "cve": "CVE-2021-0001", "pair_key": "seen-pair", "cve_year": 2021, "pair_text": "- a\n+ b"},
        {"id": "safe-seen", "project": "seen", "cve": "CVE-2021-0001", "pair_key": "seen-pair", "cve_year": 2021, "pair_text": "- a\n+ b"},
        {"id": "vuln-new", "project": "new", "cve": "CVE-2021-0002", "pair_key": "new-pair", "cve_year": 2021, "pair_text": "- c\n+ d"},
        {"id": "safe-new", "project": "new", "cve": "CVE-2021-0002", "pair_key": "new-pair", "cve_year": 2021, "pair_text": "- c\n+ d"},
    ]
    predictions = [
        {"id": "vuln-seen", "gold": 1, "vuln_probability": 0.9},
        {"id": "safe-seen", "gold": 0, "vuln_probability": 0.1},
        {"id": "vuln-new", "gold": 1, "vuln_probability": 0.7},
        {"id": "safe-new", "gold": 0, "vuln_probability": 0.3},
    ]

    report = build_report(
        train,
        eval_rows,
        predictions,
        threshold=0.6,
        margin=0.02,
        scenarios={"project_disjoint": ["project"]},
    )

    scenario = report["scenarios"]["project_disjoint"]
    assert scenario["split"]["rows_after"] == 2
    assert scenario["split"]["label_counts_after"] == {"safe": 1, "vulnerable": 1}
    assert scenario["split"]["field_filters"]["project"]["removed_overlap_rows"] == 2
    assert scenario["pair_coupled"]["coupling_counts"]["coupled_groups"] == 1

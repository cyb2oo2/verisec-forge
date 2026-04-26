from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    script_path = Path("scripts") / "build_primevul_pair_context_dataset.py"
    spec = importlib.util.spec_from_file_location("build_primevul_pair_context_dataset", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pair_context_rows_include_candidate_and_counterpart_text() -> None:
    module = _load_module()
    rows = [
        {
            "id": "vuln",
            "project": "openssl",
            "commit_id": "abc",
            "cve": "CVE-1",
            "vulnerability_type": "cwe-310",
            "code": "return TLS1_get_version(s);",
            "has_vulnerability": True,
        },
        {
            "id": "safe",
            "project": "openssl",
            "commit_id": "abc",
            "cve": "CVE-1",
            "vulnerability_type": "cwe-310",
            "code": "return s->method->version;",
            "has_vulnerability": False,
        },
    ]

    selected, summary = module.build_pair_context_rows(rows, per_label_count=1, seed=7)

    assert summary["usable_pair_group_count"] == 1
    assert summary["selected"] == {"vulnerable": 1, "safe": 1, "total": 2}
    assert {row["pair_counterpart_id"] for row in selected} == {"vuln", "safe"}
    assert all("Candidate function:" in row["pair_text"] for row in selected)
    assert all("Paired counterpart function:" in row["pair_text"] for row in selected)


def test_pair_context_text_modes_isolate_inputs() -> None:
    module = _load_module()
    candidate = {
        "project": "openssl",
        "commit_id": "abc",
        "cve": "CVE-1",
        "vulnerability_type": "cwe-310",
        "code": "return TLS1_get_version(s);",
    }
    counterpart = {
        "project": "openssl",
        "commit_id": "abc",
        "cve": "CVE-1",
        "vulnerability_type": "cwe-310",
        "code": "return s->method->version;",
    }

    candidate_only = module.build_pair_text(candidate, counterpart, text_mode="candidate_only")
    counterpart_only = module.build_pair_text(candidate, counterpart, text_mode="counterpart_only")
    metadata_only = module.build_pair_text(candidate, counterpart, text_mode="metadata_only")
    diff_only = module.build_pair_text(candidate, counterpart, text_mode="diff_only")
    diff_no_metadata = module.build_pair_text(candidate, counterpart, text_mode="diff_no_metadata")
    candidate_plus_diff = module.build_pair_text(candidate, counterpart, text_mode="candidate_plus_diff")

    assert "TLS1_get_version" in candidate_only
    assert "s->method->version" not in candidate_only
    assert "s->method->version" in counterpart_only
    assert "TLS1_get_version" not in counterpart_only
    assert "CVE-1" in metadata_only
    assert "TLS1_get_version" not in metadata_only
    assert "s->method->version" not in metadata_only
    assert "--- paired_counterpart" in diff_only
    assert "+++ candidate" in diff_only
    assert "Candidate function:" not in diff_only
    assert "--- paired_counterpart" in diff_no_metadata
    assert "+++ candidate" in diff_no_metadata
    assert "Project:" not in diff_no_metadata
    assert "CVE-1" not in diff_no_metadata
    assert "cwe-310" not in diff_no_metadata
    assert "Candidate function:" in candidate_plus_diff
    assert "Unified diff" in candidate_plus_diff

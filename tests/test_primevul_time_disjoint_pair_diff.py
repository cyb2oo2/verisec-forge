from __future__ import annotations

from scripts.build_primevul_time_disjoint_pair_diff import build_time_disjoint, cve_year


def test_cve_year_extracts_year() -> None:
    assert cve_year("CVE-2021-1234") == 2021
    assert cve_year("not-a-cve") is None


def test_time_disjoint_split_has_no_year_or_pair_overlap() -> None:
    rows = [
        {
            "id": "old-vuln",
            "project": "openssl",
            "commit_id": "old",
            "cve": "CVE-2020-0001",
            "vulnerability_type": "cwe-120",
            "code": "strcpy(dst, src);",
            "has_vulnerability": True,
        },
        {
            "id": "old-safe",
            "project": "openssl",
            "commit_id": "old",
            "cve": "CVE-2020-0001",
            "vulnerability_type": "cwe-120",
            "code": "bounded_copy(dst, src, len);",
            "has_vulnerability": False,
        },
        {
            "id": "new-vuln",
            "project": "openssl",
            "commit_id": "new",
            "cve": "CVE-2021-0001",
            "vulnerability_type": "cwe-787",
            "code": "sprintf(buf, value);",
            "has_vulnerability": True,
        },
        {
            "id": "new-safe",
            "project": "openssl",
            "commit_id": "new",
            "cve": "CVE-2021-0001",
            "vulnerability_type": "cwe-787",
            "code": "snprintf(buf, size, value);",
            "has_vulnerability": False,
        },
    ]

    train, eval_rows, summary = build_time_disjoint(
        rows,
        train_max_year=2020,
        eval_min_year=2021,
        train_per_label=1,
        eval_per_label=1,
        seed=7,
        text_mode="diff_only",
    )

    assert len(train) == 2
    assert len(eval_rows) == 2
    assert summary["overlap"]["year_overlap"] == []
    assert summary["overlap"]["pair_key_overlap"] == 0
    assert summary["overlap"]["project_overlap"] == 1

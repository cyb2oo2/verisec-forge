from __future__ import annotations

from scripts.build_deltasecommits_pair_diff import build_rows, split_by_pair_key, normalize_code_for_diff


def test_deltasecommits_builder_creates_balanced_pair_rows() -> None:
    source = [
        {
            "prior_version": "int f(){return strcpy(a,b);}",
            "after_version": "int f(){return safe_copy(a,b);}",
            "vuln_id": "CVE-2099-0001",
            "cwe": "CWE-120",
            "project": "demo",
            "commit_sha": "abc",
            "file_extension": "c",
        },
        {
            "prior_version": "ignored",
            "after_version": "ignored",
            "file_extension": "py",
        },
    ]

    rows, summary = build_rows(source, extensions={"c"}, text_mode="diff_only")

    assert len(rows) == 2
    assert summary["labels"] == {"safe": 1, "vulnerable": 1}
    assert {row["has_vulnerability"] for row in rows} == {True, False}
    assert all("Unified diff:" in row["pair_text"] for row in rows)
    assert rows[0]["pair_key"] == rows[1]["pair_key"]
    assert "--- paired_counterpart\n+++ candidate\n@@" in rows[0]["pair_text"]


def test_deltasecommits_builder_expands_single_line_c_like_snapshots() -> None:
    normalized = normalize_code_for_diff("int f(){return 1;}")

    assert "{" in normalized
    assert "return 1;" in normalized
    assert normalized.count("\n") >= 3


def test_deltasecommits_split_is_pair_key_disjoint() -> None:
    rows = [
        {"id": "a:v", "pair_key": "a", "has_vulnerability": True},
        {"id": "a:s", "pair_key": "a", "has_vulnerability": False},
        {"id": "b:v", "pair_key": "b", "has_vulnerability": True},
        {"id": "b:s", "pair_key": "b", "has_vulnerability": False},
    ]

    train, eval_rows = split_by_pair_key(rows, eval_fraction=0.5, seed=1)
    train_keys = {row["pair_key"] for row in train}
    eval_keys = {row["pair_key"] for row in eval_rows}

    assert train_keys
    assert eval_keys
    assert not (train_keys & eval_keys)

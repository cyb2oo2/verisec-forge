from scripts.build_patcheval_pair_diff import pair_rows_from_example


def test_patcheval_pair_rows_create_vulnerable_and_secure_candidates():
    example = {
        "cve_id": "CVE-2099-0001",
        "cwe_info": {"CWE-79": {"name": "xss"}},
        "repo": "https://example.test/repo",
        "programming_language": "Python",
        "vul_func": [{"id": "v1", "commit": "a", "file_path": "app.py", "snippet": "return user"}],
        "fix_func": [{"id": "f1", "commit": "b", "file_path": "app.py", "snippet": "return escape(user)"}],
    }

    rows = pair_rows_from_example(example, example_index=0)

    assert len(rows) == 2
    assert {row["has_vulnerability"] for row in rows} == {True, False}
    assert all(row["source_dataset"] == "ByteDance/PatchEval" for row in rows)
    assert all("Unified diff:" in row["pair_text"] for row in rows)

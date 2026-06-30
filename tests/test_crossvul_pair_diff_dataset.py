from scripts.build_crossvul_pair_diff import changed_line_bucket, pair_rows_from_example


def test_crossvul_pair_rows_create_vulnerable_and_secure_candidates():
    example = {
        "cwe_id": "CWE-79",
        "language": "c",
        "vulnerable_code": "int main() {\n  return strcpy(buf, user);\n}\n",
        "fixed_code": "int main() {\n  return strncpy(buf, user, sizeof(buf));\n}\n",
        "file_pair_id": "1234_0",
    }

    rows = pair_rows_from_example(example)

    assert len(rows) == 2
    assert {row["has_vulnerability"] for row in rows} == {True, False}
    assert all(row["source_dataset"] == "crossvul" for row in rows)
    assert all(row["pair_key"] == "crossvul-1234_0" for row in rows)
    assert all("Unified diff:" in row["pair_text"] for row in rows)


def test_crossvul_pair_rows_skip_identical_or_empty_code():
    same_code = {
        "cwe_id": "CWE-79",
        "language": "c",
        "vulnerable_code": "int main() { return 0; }",
        "fixed_code": "int main() { return 0; }",
        "file_pair_id": "same",
    }
    empty_code = {
        "cwe_id": "CWE-79",
        "language": "c",
        "vulnerable_code": "",
        "fixed_code": "int main() { return 0; }",
        "file_pair_id": "empty",
    }

    assert pair_rows_from_example(same_code) == []
    assert pair_rows_from_example(empty_code) == []


def test_changed_line_bucket_counts_diff_lines_only():
    pair_text = "Unified diff:\n--- paired_counterpart\n+++ candidate\n@@\n-old\n+new\n"

    assert changed_line_bucket(pair_text) == "00-02"

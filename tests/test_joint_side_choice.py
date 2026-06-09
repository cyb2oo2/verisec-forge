from vrf.joint_reasoning import (
    build_side_choice_examples,
    build_synthetic_side_choice_examples,
    extract_unified_diff,
    reverse_unified_diff,
    summarize_side_choice_examples,
)


def _rows():
    return [
        {
            "id": "safe::pairctx",
            "pair_counterpart_id": "vuln",
            "pair_text": "Project: p\nUnified diff:\n--- paired_counterpart+++ candidate@@ -1 +1 @@\n-bad\n+good\n",
            "has_vulnerability": False,
        },
        {
            "id": "vuln::pairctx",
            "pair_counterpart_id": "safe",
            "pair_text": "Project: p\nUnified diff:\n--- paired_counterpart+++ candidate@@ -1 +1 @@\n-good\n+bad\n",
            "has_vulnerability": True,
        },
    ]


def test_extract_unified_diff_removes_metadata_and_candidate_names():
    diff = extract_unified_diff(_rows()[0]["pair_text"])
    assert "Project:" not in diff
    assert "candidate" not in diff
    assert diff.startswith("--- Side A\n+++ Side B")


def test_build_side_choice_examples_is_balanced_and_reversible():
    rows = build_side_choice_examples("pair", _rows())
    assert [row["label"] for row in rows] == [0, 1]
    assert {row["vulnerable_side"] for row in rows} == {"A", "B"}
    assert all("Project:" not in row["text"] for row in rows)
    summary = summarize_side_choice_examples(rows)
    assert summary == {
        "examples": 2,
        "unique_pairs": 1,
        "label_counts": {"0": 1, "1": 1},
        "examples_per_pair": 2.0,
    }


def test_synthetic_reverse_flips_diff_and_label():
    row = _rows()[1]
    examples = build_synthetic_side_choice_examples(row)
    assert [example["label"] for example in examples] == [1, 0]
    assert "-good\n+bad" in examples[0]["text"]
    assert "+good\n-bad" in examples[1]["text"]
    assert reverse_unified_diff("@@ -1,2 +3,4 @@ x") == "@@ -3,4 +1,2 @@ x"

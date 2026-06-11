from vrf.relational_benchmark import (
    build_canonical_pair,
    build_interventions,
    changed_line_occurrences,
    render_pair,
    sample_balanced_stress,
    sample_representative,
    sampling_diagnostics,
    swap_pair,
)


def pair_rows(
    key: str,
    *,
    project: str = "demo",
    cwe: str = "CWE-20",
    code_size: int = 1,
):
    prefix = "\n".join(f"int pad_{index};" for index in range(code_size))
    return [
        {
            "id": f"{key}:vulnerable",
            "pair_key": key,
            "project": project,
            "cve": "CVE-2024-1000",
            "cwe": cwe,
            "programming_language": "C",
            "code": f"{prefix}\nint f(int x) {{ return data[x]; }}\n",
            "has_vulnerability": True,
        },
        {
            "id": f"{key}:secure",
            "pair_key": key,
            "project": project,
            "cve": "CVE-2024-1000",
            "cwe": cwe,
            "programming_language": "C",
            "code": (
                f"{prefix}\nint f(int x) {{ if (x < 0) return -1; "
                "return data[x]; }\n"
            ),
            "has_vulnerability": False,
        },
    ]


def test_canonical_swap_changes_only_side_order_contract():
    pair = build_canonical_pair("pair-1", pair_rows("pair-1"), dataset="demo")
    swapped = swap_pair(pair)

    assert pair.side_a.id == swapped.side_b.id
    assert pair.side_b.id == swapped.side_a.id
    assert pair.gold_riskier_side != swapped.gold_riskier_side
    assert "Output one label" in render_pair(pair)
    assert "Output one label" in render_pair(swapped)


def test_interventions_are_tokenizer_neutral_and_runtime_described():
    pair = build_canonical_pair("pair-2", pair_rows("pair-2"), dataset="demo")
    interventions = build_interventions(pair)
    by_template = {row.template: row for row in interventions}

    assert "canonical_renderer_swap_v2" in by_template
    assert "length_only_end_numbered_comments_v2" in by_template
    pressure = by_template["budget_75pct_before_diff_v2"]
    assert pressure.expected_relation == "context_pressure"
    assert pressure.text == render_pair(pair)
    assert pressure.runtime_transform["target_budget_ratio"] == 0.75
    assert "token_accounting" not in pressure.to_dict()


def test_changed_line_occurrences_track_duplicate_lines_separately():
    text = "header\n-return 0;\n context\n-return 0;\n+return 1;\n"
    occurrences = changed_line_occurrences(text)

    assert [row["occurrence"] for row in occurrences] == [0, 1, 2]
    assert occurrences[0]["char_start"] != occurrences[1]["char_start"]
    assert occurrences[0]["text"] == occurrences[1]["text"]


def test_representative_sampling_is_seeded_and_input_order_independent():
    pairs = [
        build_canonical_pair(
            f"pair-{index}",
            pair_rows(f"pair-{index}", project=f"project-{index % 3}"),
            dataset="demo",
        )
        for index in range(12)
    ]
    first = sample_representative(pairs, limit=6, seed=7)
    second = sample_representative(list(reversed(pairs)), limit=6, seed=7)

    assert [pair.pair_key for pair in first] == [
        pair.pair_key for pair in second
    ]


def test_balanced_stress_sampling_limits_project_concentration():
    pairs = [
        build_canonical_pair(
            f"pair-{index}",
            pair_rows(
                f"pair-{index}",
                project="dominant" if index < 30 else f"project-{index}",
                cwe=f"CWE-{index % 8}",
                code_size=1 + index * 3,
            ),
            dataset="demo",
        )
        for index in range(50)
    ]
    selected = sample_balanced_stress(pairs, limit=20, seed=7)
    diagnostics = sampling_diagnostics(
        selected,
        suite="balanced_stress",
        target_diff_buckets=["00-02", "03-05", "06-10", "11-25", "26+"],
        target_character_buckets=["<=1k", "1k-4k", "4k-16k", "16k+"],
    )

    assert len(selected) == 20
    assert diagnostics["maximum_project_concentration"] <= 0.10
    assert diagnostics["effective_projects"] > 5

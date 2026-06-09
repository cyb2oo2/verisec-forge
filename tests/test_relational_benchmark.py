from vrf.relational_benchmark import (
    build_canonical_pair,
    build_interventions,
    render_pair,
    sample_pairs,
    swap_pair,
    token_accounting,
)


def encode(text: str) -> list[int]:
    return [sum(ord(char) for char in token) % 997 for token in text.split()]


def pair_rows(key: str, *, project: str = "demo"):
    return [
        {
            "id": f"{key}:vulnerable",
            "pair_key": key,
            "project": project,
            "cve": "CVE-2024-1000",
            "cwe": "CWE-20",
            "programming_language": "C",
            "code": "int f(int x) { return data[x]; }\n",
            "has_vulnerability": True,
        },
        {
            "id": f"{key}:secure",
            "pair_key": key,
            "project": project,
            "cve": "CVE-2024-1000",
            "cwe": "CWE-20",
            "programming_language": "C",
            "code": "int f(int x) { if (x < 0) return -1; return data[x]; }\n",
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


def test_interventions_record_validation_and_token_accounting():
    pair = build_canonical_pair("pair-2", pair_rows("pair-2"), dataset="demo")
    interventions = build_interventions(pair, encode=encode, max_length=128)
    by_template = {row.template: row for row in interventions}

    assert "canonical_renderer_swap_v1" in by_template
    assert "length_only_end_numbered_comments_v1" in by_template
    assert "budget_75pct_before_diff_v1" in by_template
    assert by_template["canonical_renderer_swap_v1"].expected_relation == "equivariant_swap"
    assert by_template["length_only_end_numbered_comments_v1"].validation_tier == 1
    assert by_template["budget_75pct_before_diff_v1"].token_accounting["token_delta"] > 0


def test_token_accounting_detects_truncated_critical_lines():
    original = "header\n-old\n+new\n"
    transformed = " ".join(["padding"] * 20) + "\n-old\n+new\n"
    accounting = token_accounting(original, transformed, encode=encode, max_length=5)

    assert accounting["truncated_tokens"] > 0
    assert accounting["critical_hunk_truncated"] is True


def test_balanced_sampling_is_seeded_and_not_input_order_dependent():
    pairs = [
        build_canonical_pair(
            f"pair-{index}",
            pair_rows(f"pair-{index}", project=f"project-{index % 3}"),
            dataset="demo",
        )
        for index in range(12)
    ]
    first = sample_pairs(
        pairs,
        limit=6,
        seed=7,
        mode="balanced",
        encode=encode,
        stratify_by=["project", "diff_bucket"],
    )
    second = sample_pairs(
        list(reversed(pairs)),
        limit=6,
        seed=7,
        mode="balanced",
        encode=encode,
        stratify_by=["project", "diff_bucket"],
    )

    assert [pair.pair_key for pair in first] == [pair.pair_key for pair in second]
    assert len({pair.project for pair in first}) == 3

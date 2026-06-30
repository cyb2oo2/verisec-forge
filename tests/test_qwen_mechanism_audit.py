from vrf.qwen_mechanism_audit import (
    NEUTRAL_PADDING,
    clang_format_code,
    expand_c_like_separators,
    padding_variants,
)
from scripts.build_qwen_mechanism_side_swap_terminal_phrase_audit import build_interaction_rows


def test_padding_variants_use_identical_neutral_content():
    base = (
        "Task\n\nMetadata\n\nUnified diff from Side A to Side B:\n"
        "--- Side A\n+++ Side B\n@@ -1 +1 @@\n-old\n+new\n"
    )
    variants = padding_variants(base)

    assert len(variants) == 7
    for text in variants.values():
        assert text.count(NEUTRAL_PADDING) == 1
    assert variants["padding_post_diff"].endswith(
        NEUTRAL_PADDING + "\n"
    )
    assert variants["padding_post_diff_end_patch"].endswith(
        "[END_PATCH]\n"
    )
    assert "padding_post_diff_terminal_phrase" in variants
    assert "padding_mid_diff_malformed_stress" in variants


def test_separator_expansion_turns_single_line_c_into_multiple_lines():
    expanded = expand_c_like_separators(
        "int f(){int x=0;return x;}"
    )

    assert expanded.count("\n") >= 4
    assert "int x=0;" in expanded


def test_clang_format_reports_fallback_status(tmp_path):
    result = clang_format_code(
        "int f(){return 0;}",
        executable=tmp_path / "missing-clang-format",
    )

    assert result.success is False
    assert result.fallback_used is True


def test_build_interaction_rows_crosses_swap_and_terminal_phrase():
    base = {
        "id": "audit::primevul::p1::canonical",
        "dataset": "primevul",
        "pair_key": "p1",
        "cluster_id": "c1",
        "gold_riskier_side": "A",
        "text": (
            "Task\n\nMetadata\n\nUnified diff from Side A to Side B:\n"
            "--- Side A\n+++ Side B\n@@ -1 +1 @@\n-old\n+new\n"
        ),
    }
    swap = {
        "id": "audit::primevul::p1::side_swap",
        "gold_riskier_side": "B",
        "text": (
            "Task\n\nMetadata\n\nUnified diff from Side A to Side B:\n"
            "--- Side A\n+++ Side B\n@@ -1 +1 @@\n-new\n+old\n"
        ),
    }
    swaps = {base["id"]: swap}

    rows = build_interaction_rows([base], swaps)

    by_variant = {row["audit_variant"]: row for row in rows}
    assert set(by_variant) == {
        "side_swap_padding_post_diff_terminal_phrase",
        "side_swap",
        "padding_post_diff_terminal_phrase",
        "canonical",
    }

    # The canonical row must be expected_relation="identity" -- this is what
    # materialize_relational_runtime.py keys its base lookup on; getting this
    # wrong (e.g. leaving the default "invariant") breaks runtime
    # materialization with a KeyError on base_id lookup.
    assert by_variant["canonical"]["expected_relation"] == "identity"

    # The combined variant must apply the terminal-phrase padding to the
    # already-swapped text, not the canonical text.
    combined_text = by_variant["side_swap_padding_post_diff_terminal_phrase"]["text"]
    assert "+old" in combined_text  # swapped content present
    assert "Unified diff complete." in combined_text  # terminal phrase applied
    assert by_variant["side_swap_padding_post_diff_terminal_phrase"]["gold_riskier_side"] == "B"
    assert by_variant["side_swap_padding_post_diff_terminal_phrase"]["expected_relation"] == "equivariant_swap"

from vrf.qwen_mechanism_audit import (
    NEUTRAL_PADDING,
    expand_c_like_separators,
    padding_variants,
)


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


def test_separator_expansion_turns_single_line_c_into_multiple_lines():
    expanded = expand_c_like_separators(
        "int f(){int x=0;return x;}"
    )

    assert expanded.count("\n") >= 4
    assert "int x=0;" in expanded

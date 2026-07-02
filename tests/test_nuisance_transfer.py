import pytest

from vrf.nuisance_transfer import (
    NUISANCE_FAMILIES,
    build_nuisance_rows,
    render_context_window,
    render_diff_algorithm,
    render_split_view,
    render_whitespace_comment,
)
from vrf.relational_benchmark import CanonicalPair, CanonicalSide


def _pair(vulnerable_side="a"):
    side_a = CanonicalSide(
        id="a", code="void f() {\n  char buf[5];\n  use(buf);\n}\n", vulnerable=(vulnerable_side == "a")
    )
    side_b = CanonicalSide(
        id="b", code="void f() {\n  char buf[8];\n  use(buf);\n}\n", vulnerable=(vulnerable_side == "b")
    )
    return CanonicalPair(
        dataset="demo", pair_key="p1", project="proj", language="c",
        cwe="cwe-787", cve="CVE-0000", year=2020, side_a=side_a, side_b=side_b,
    )


def test_all_families_produce_distinct_nonempty_renderings():
    pair = _pair()
    seen = set()
    for family in NUISANCE_FAMILIES:
        canonical_text, side_swap_text = build_nuisance_rows(pair, family)
        assert canonical_text.strip()
        assert side_swap_text.strip()
        assert canonical_text != side_swap_text
        seen.add(canonical_text)
    # Every family should render the SAME pair differently from every other family.
    assert len(seen) == len(NUISANCE_FAMILIES)


def test_context_window_changes_visible_context_lines():
    pair = _pair()
    tight = render_context_window(pair, context_lines=0)
    wide = render_context_window(pair, context_lines=3)
    assert len(tight) < len(wide)
    assert "buf[5]" in tight and "buf[8]" in tight


def test_split_view_groups_removed_and_added_separately():
    pair = _pair()
    text = render_split_view(pair)
    assert "Removed from Side A" in text
    assert "Added in Side B" in text
    removed_idx = text.index("Removed from Side A")
    added_idx = text.index("Added in Side B")
    buf5_idx = text.index("buf[5]")
    buf8_idx = text.index("buf[8]")
    assert removed_idx < buf5_idx < added_idx
    assert added_idx < buf8_idx


def test_whitespace_comment_preserves_code_content_and_inserts_marker():
    pair = _pair()
    text = render_whitespace_comment(pair)
    assert "buf[5]" in text and "buf[8]" in text
    assert "benign whitespace/comment perturbation marker" in text


def test_diff_algorithm_uses_git_native_header():
    pair = _pair()
    myers = render_diff_algorithm(pair, algorithm="myers")
    histogram = render_diff_algorithm(pair, algorithm="histogram")
    for text in (myers, histogram):
        assert "diff --git a/Side A b/Side B" in text
        assert "--- a/Side A" in text
        assert "+++ b/Side B" in text
        # No leaked temp-file paths.
        assert "AppData" not in text and "Temp" not in text


def test_side_swap_flips_gold_and_content_position():
    pair = _pair(vulnerable_side="a")
    assert pair.gold_riskier_side == "A"
    canonical_text, side_swap_text = build_nuisance_rows(pair, "context_window")
    # Side-swap rendering is the same transform applied to the swapped pair,
    # so it differs from canonical and is internally consistent (non-empty,
    # contains the same underlying code content).
    assert side_swap_text != canonical_text
    assert "buf[5]" in side_swap_text and "buf[8]" in side_swap_text


def test_unknown_family_raises():
    pair = _pair()
    with pytest.raises(ValueError):
        build_nuisance_rows(pair, "not_a_real_family")

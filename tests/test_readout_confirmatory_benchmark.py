from scripts.build_readout_confirmatory_benchmark import (
    SUFFIX_SPECS,
    suffix_text,
)


def test_confirmatory_suffixes_are_distinct_and_post_diff():
    base = "Unified diff from Side A to Side B:\n-old\n+new\n"
    rendered = {
        name: suffix_text(base, spec) for name, spec in SUFFIX_SPECS.items()
    }

    assert len(set(rendered.values())) == 3
    assert all(text.startswith(base.rstrip()) for text in rendered.values())
    assert all(
        "Independent neutral review context:" in text
        for text in rendered.values()
    )

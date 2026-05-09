from __future__ import annotations

from scripts.build_primevul_progressive_controls_chart import kind_for_stage, render_svg, wrap_text


def test_wrap_text_keeps_words_and_splits_long_text() -> None:
    lines = wrap_text("alpha beta gamma delta", 12)

    assert lines == ["alpha beta", "gamma delta"]


def test_kind_for_stage_maps_known_stages() -> None:
    assert kind_for_stage("Same-source baseline") == "artifact"
    assert kind_for_stage("Shortcut controls") == "control"
    assert kind_for_stage("Pair-coupled decoding") == "system"
    assert kind_for_stage("Safe flip gate") == "audit"


def test_render_svg_includes_stage_and_metric() -> None:
    payload = {
        "rows": [
            {
                "stage": "Pair-coupled decoding",
                "question": "Does it improve?",
                "key_metric": "mean_balanced_accuracy",
                "value": 0.8572,
                "supporting_metric": "delta=0.0348",
                "interpretation": "Stable row-level and group-level gains.",
            }
        ]
    }

    svg = render_svg(payload)

    assert svg.startswith("<svg")
    assert "PrimeVul Progressive Controls" in svg
    assert "Pair-coupled decoding" in svg
    assert "0.8572" in svg

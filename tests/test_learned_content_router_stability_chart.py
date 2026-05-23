from scripts.build_learned_content_router_stability_chart import extract_rows, render_svg


def _payload(feature_mode, half_ba, full_ba):
    def summary(value):
        return {
            "learned_ba": {"mean": value, "min": value, "max": value},
            "routing_row_accuracy": {"mean": 0.9},
            "learned_group_all_correct": {"mean": 0.85},
        }

    return {
        "protocol": {"feature_mode": feature_mode},
        "summary_by_train_fraction": {
            "0.5": summary(half_ba),
            "1.0": summary(full_ba),
        },
    }


def test_learned_content_router_stability_chart_renders_key_claims():
    rows = extract_rows(
        [
            _payload("char_3_5", 0.8649, 0.8649),
            _payload("token_1_2", 0.8630, 0.8635),
            _payload("diff_line_markers", 0.8634, 0.8642),
        ]
    )

    svg = render_svg(rows)

    assert len(rows) == 6
    assert svg.startswith("<svg")
    assert "Learned Router Robustness" in svg
    assert "char n-grams" in svg
    assert "0.8649" in svg
    assert "single matched-mixed" in svg

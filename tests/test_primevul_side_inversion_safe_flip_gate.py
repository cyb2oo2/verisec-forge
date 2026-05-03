from __future__ import annotations

from scripts.evaluate_primevul_side_inversion_safe_flip_gate import annotate_rows, build_report, should_accept


def row(*, pair_key: str, accept_flip: bool, prompt: str = "", row_id: str = "r") -> dict:
    return {
        "id": row_id,
        "pair_key": pair_key,
        "accept_flip": accept_flip,
        "prompt": prompt,
    }


def high_evidence_prompt() -> str:
    return "\n".join(
        [
            "Side A windows:",
            "Signals: risk=0 safety=5 labels=candidate_adds_protection",
            "Side B windows:",
            "Signals: risk=6 safety=0 labels=candidate_removes_protection",
        ]
    )


def test_should_accept_uses_repeat_or_evidence() -> None:
    rows = [row(pair_key="stable", accept_flip=True), row(pair_key="stable", accept_flip=True)]
    counts = {"stable": 2}

    assert should_accept(rows[0], counts, repeat_threshold=2, evidence_threshold=10.0) is True
    assert should_accept(row(pair_key="single", accept_flip=True, prompt=high_evidence_prompt()), {"single": 1}, repeat_threshold=2, evidence_threshold=10.0) is True


def test_should_accept_can_condition_repeat_on_evidence() -> None:
    rows = [row(pair_key="stable", accept_flip=True), row(pair_key="stable", accept_flip=True)]
    counts = {"stable": 2}

    assert (
        should_accept(
            rows[0],
            counts,
            repeat_threshold=2,
            evidence_threshold=10.0,
            repeat_evidence_threshold=1.0,
        )
        is False
    )
    assert (
        should_accept(
            row(pair_key="stable", accept_flip=True, prompt=high_evidence_prompt()),
            counts,
            repeat_threshold=2,
            evidence_threshold=20.0,
            repeat_evidence_threshold=1.0,
        )
        is True
    )


def test_annotate_rows_marks_repair_and_harm() -> None:
    rows = [
        row(pair_key="a", accept_flip=True, prompt=high_evidence_prompt(), row_id="good"),
        row(pair_key="b", accept_flip=False, prompt=high_evidence_prompt(), row_id="bad"),
    ]

    annotated = annotate_rows(rows, repeat_threshold=3, evidence_threshold=10.0)

    assert annotated[0]["would_repair_side_error"] is True
    assert annotated[1]["would_introduce_side_error"] is True


def test_build_report_tracks_net_gain() -> None:
    rows = [
        row(pair_key="stable", accept_flip=True, row_id="a1"),
        row(pair_key="stable", accept_flip=True, row_id="a2"),
        row(pair_key="stable", accept_flip=True, row_id="a3"),
        row(pair_key="reject", accept_flip=False, row_id="b1"),
    ]

    report = build_report(rows, repeat_threshold=3, evidence_threshold=10.0)

    assert report["summary"]["accepted_rows"] == 3
    assert report["summary"]["repaired_side_error_rows"] == 3
    assert report["summary"]["introduced_side_error_rows"] == 0
    assert report["summary"]["net_row_gain_if_applied"] == 3

from __future__ import annotations

from scripts.analyze_primevul_safe_flip_gate_failures import build_report


def row(row_id: str, *, pair_key: str, accept_flip: bool) -> dict:
    return {
        "id": row_id,
        "pair_key": pair_key,
        "accept_flip": accept_flip,
        "prompt": "",
        "project": "proj",
    }


def test_build_report_tracks_false_accepts_and_misses() -> None:
    rows = [
        row("good", pair_key="p1", accept_flip=True),
        row("bad", pair_key="p2", accept_flip=False),
        row("miss", pair_key="p3", accept_flip=True),
        row("reject", pair_key="p4", accept_flip=False),
    ]
    gate = {"accepted_rows": [{"id": "good"}, {"id": "bad"}]}

    report = build_report(rows, gate)

    assert report["summary"]["true_accepts"] == 1
    assert report["summary"]["false_accepts"] == 1
    assert report["summary"]["missed_true_flips"] == 1
    assert report["summary"]["true_rejects"] == 1
    assert report["false_accepts"][0]["id"] == "bad"

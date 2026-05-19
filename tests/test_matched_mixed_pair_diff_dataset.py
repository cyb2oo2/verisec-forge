from __future__ import annotations

from scripts.build_matched_mixed_pair_diff_dataset import build_dataset


def test_matched_mixed_dataset_samples_short_primevul_balanced_rows() -> None:
    prime_rows = [
        {"id": "p-safe-short", "pair_key": "p1", "has_vulnerability": False, "pair_text": "--- a\n+++ b\n-a\n+b"},
        {"id": "p-safe-long", "pair_key": "p2", "has_vulnerability": False, "pair_text": "x" * 100},
        {"id": "p-vuln-short", "pair_key": "p3", "has_vulnerability": True, "pair_text": "--- a\n+++ b\n-a\n+b"},
        {"id": "p-vuln-long", "pair_key": "p4", "has_vulnerability": True, "pair_text": "x" * 100},
    ]
    delta_rows = [
        {"id": "d-safe", "pair_key": "d1", "has_vulnerability": False, "pair_text": "--- a\n+++ b\n-a\n+b"},
        {"id": "d-vuln", "pair_key": "d1", "has_vulnerability": True, "pair_text": "--- a\n+++ b\n-a\n+b"},
    ]

    rows, summary = build_dataset(
        prime_rows=prime_rows,
        delta_rows=delta_rows,
        prime_per_label=1,
        max_prime_chars=20,
        seed=3,
    )

    assert len(rows) == 4
    assert summary["labels"] == {"safe": 2, "vulnerable": 2}
    assert summary["source_counts"] == {"primevul_time_short": 2, "deltasecommits": 2}
    assert summary["prime_sampling"]["eligible_rows"] == 2
    assert len({row["id"] for row in rows}) == 4
    assert all(row.get("changed_line_bucket") == "00-02" for row in rows)

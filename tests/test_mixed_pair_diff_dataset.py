from __future__ import annotations

import json
from pathlib import Path

from scripts.build_mixed_pair_diff_dataset import build_mixed_rows


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")


def test_build_mixed_rows_prefixes_ids_and_pair_keys(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    _write_jsonl(
        left,
        [
            {"id": "row-1", "pair_key": "pair-1", "has_vulnerability": True, "pair_text": "a"},
            {"id": "row-2", "pair_key": "pair-1", "has_vulnerability": False, "pair_text": "b"},
        ],
    )
    _write_jsonl(
        right,
        [
            {"id": "row-1", "pair_key": "pair-1", "has_vulnerability": True, "pair_text": "c"},
            {"id": "row-2", "pair_key": "pair-1", "has_vulnerability": False, "pair_text": "d"},
        ],
    )

    rows, summary = build_mixed_rows([("left", left), ("right", right)], seed=7)

    assert len(rows) == 4
    assert summary["labels"] == {"safe": 2, "vulnerable": 2}
    assert summary["source_counts"] == {"left": 2, "right": 2}
    assert len({row["id"] for row in rows}) == 4
    assert {row["source_dataset"] for row in rows} == {"left", "right"}
    assert {row["pair_key"] for row in rows} == {"left:pair-1", "right:pair-1"}

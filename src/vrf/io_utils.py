from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable


def ensure_parent(path: str | Path) -> Path:
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    return file_path


def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: str | Path, payload: Any) -> None:
    file_path = ensure_parent(path)
    with file_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def append_jsonl(path: str | Path, row: dict[str, Any]) -> None:
    file_path = ensure_parent(path)
    with file_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> None:
    file_path = ensure_parent(path)
    with file_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_csv(path: str | Path, rows: list[dict[str, Any]]) -> None:
    file_path = ensure_parent(path)
    if not rows:
        with file_path.open("w", encoding="utf-8", newline="") as handle:
            handle.write("")
        return
    with file_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

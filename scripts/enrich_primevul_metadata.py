from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from vrf.io_utils import read_jsonl, write_jsonl


METADATA_FIELDS = (
    "project",
    "commit_id",
    "project_url",
    "commit_url",
    "commit_message",
    "func_hash",
    "file_name",
    "file_hash",
    "cve",
    "cve_desc",
    "nvd_url",
)


def load_raw_metadata(raw_dir: Path) -> dict[str, dict[str, Any]]:
    metadata: dict[str, dict[str, Any]] = {}
    for path in raw_dir.glob("primevul_*.jsonl"):
        if "paired" in path.stem:
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                raw_id = row.get("id", row.get("idx"))
                if raw_id is None:
                    continue
                metadata[str(raw_id)] = {
                    field: row.get(field)
                    for field in METADATA_FIELDS
                    if row.get(field) not in {None, ""}
                }
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill raw PrimeVul metadata into processed JSONL rows.")
    parser.add_argument("--input", required=True, help="Processed PrimeVul JSONL")
    parser.add_argument("--raw-dir", required=True, help="Raw PrimeVul directory")
    parser.add_argument("--output", required=True, help="Metadata-enriched JSONL")
    args = parser.parse_args()

    metadata_by_id = load_raw_metadata(Path(args.raw_dir))
    rows_out: list[dict[str, Any]] = []
    matched = 0
    for row in read_jsonl(args.input):
        enriched = dict(row)
        metadata = metadata_by_id.get(str(row["id"]))
        if metadata:
            matched += 1
            enriched.update(metadata)
        rows_out.append(enriched)

    write_jsonl(args.output, rows_out)
    print(
        json.dumps(
            {
                "input": args.input,
                "output": args.output,
                "rows": len(rows_out),
                "metadata_matched": matched,
                "metadata_match_rate": round(matched / len(rows_out), 4) if rows_out else 0.0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

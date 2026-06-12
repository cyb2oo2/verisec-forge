from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_jsonl


RENAMES = {
    "padding_mid_diff": "padding_mid_diff_malformed_stress",
    "padding_post_diff_restored_ending": "padding_post_diff_terminal_phrase",
}


def migrate(rows):
    migrated = []
    for row in rows:
        row = dict(row)
        for old, new in RENAMES.items():
            suffix = f"::{old}"
            if str(row["id"]).endswith(suffix):
                row["id"] = str(row["id"])[: -len(suffix)] + f"::{new}"
                break
        migrated.append(row)
    return migrated


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Migrate renamed Qwen mechanism prediction IDs."
    )
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    for raw_path in args.paths:
        path = ROOT / raw_path
        rows = migrate(read_jsonl(path))
        write_jsonl(path, rows)
        print(json.dumps({"status": "ok", "path": raw_path, "rows": len(rows)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

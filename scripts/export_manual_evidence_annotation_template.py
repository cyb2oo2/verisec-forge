from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.evidence_audit import ANNOTATION_TEMPLATE_FIELDS, annotation_template_rows
from vrf.io_utils import ensure_parent, read_jsonl

import csv


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export a CSV template for manual evidence annotation.",
    )
    parser.add_argument(
        "--input",
        default="data/processed/secure_code_primevul_manual_evidence_audit_v1.jsonl",
    )
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_primevul_manual_evidence_audit_v1_template.csv",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows = annotation_template_rows(read_jsonl(ROOT / args.input))
    output = ensure_parent(ROOT / args.output)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ANNOTATION_TEMPLATE_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps({"status": "ok", "output": args.output, "rows": len(rows)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

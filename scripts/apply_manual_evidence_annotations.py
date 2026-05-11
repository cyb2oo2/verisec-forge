from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.evidence_audit import apply_annotation_rows
from vrf.io_utils import read_csv, read_jsonl, write_json, write_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Apply CSV manual evidence annotations back into the audit JSONL.",
    )
    parser.add_argument(
        "--audit-input",
        default="data/processed/secure_code_primevul_manual_evidence_audit_v1.jsonl",
    )
    parser.add_argument(
        "--annotations",
        required=True,
        help="CSV file filled from scripts/export_manual_evidence_annotation_template.py.",
    )
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_primevul_manual_evidence_audit_v1.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_primevul_manual_evidence_audit_v1_apply_summary.json",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and summarize without writing the output JSONL.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    audit_rows = read_jsonl(ROOT / args.audit_input)
    annotation_rows = read_csv(ROOT / args.annotations)
    payload = apply_annotation_rows(audit_rows, annotation_rows)
    summary = {key: value for key, value in payload.items() if key != "audit_rows"}
    summary["dry_run"] = args.dry_run
    write_json(ROOT / args.summary_output, summary)
    if payload["status"] == "ok" and not args.dry_run:
        write_jsonl(ROOT / args.output, payload["audit_rows"])
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if payload["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scripts.export_manual_evidence_adjudication_template import DEFAULT_QUEUE_PATHS, load_queue_rows
from vrf.evidence_adjudication import apply_adjudication_rows
from vrf.io_utils import read_csv, write_json, write_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Apply independent adjudication CSV rows back into manual evidence review queues.",
    )
    parser.add_argument("--queues", nargs="+", default=DEFAULT_QUEUE_PATHS)
    parser.add_argument(
        "--adjudications",
        default="data/processed/secure_code_primevul_manual_evidence_adjudication_template_v1.csv",
    )
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_primevul_manual_evidence_adjudicated_queues_v1.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_primevul_manual_evidence_adjudication_apply_summary_v1.json",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    queue_rows = load_queue_rows(args.queues)
    adjudication_rows = read_csv(ROOT / args.adjudications)
    payload = apply_adjudication_rows(queue_rows, adjudication_rows)
    payload["dry_run"] = args.dry_run

    output_rows = payload.pop("queue_rows")
    if payload["status"] == "ok" and not args.dry_run:
        write_jsonl(ROOT / args.output, output_rows)
    write_json(ROOT / args.summary_output, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

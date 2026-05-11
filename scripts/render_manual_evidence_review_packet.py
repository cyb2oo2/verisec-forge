from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.evidence_audit import render_manual_evidence_review_packet
from vrf.io_utils import ensure_parent, read_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render a human-readable Markdown packet for manual evidence annotation.",
    )
    parser.add_argument(
        "--input",
        default="data/processed/secure_code_primevul_manual_evidence_audit_v1.jsonl",
    )
    parser.add_argument(
        "--output",
        default="reports/PRIMEVUL_MANUAL_EVIDENCE_REVIEW_PACKET.md",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows = read_jsonl(ROOT / args.input)
    output = ensure_parent(ROOT / args.output)
    output.write_text(render_manual_evidence_review_packet(rows), encoding="utf-8")
    print(f"wrote {args.output} rows={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

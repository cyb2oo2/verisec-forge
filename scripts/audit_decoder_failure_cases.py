from __future__ import annotations

import argparse
import json
from pathlib import Path

from vrf.decoder_failure_audit import (
    audit_decoder_identity_distortion,
    render_decoder_failure_audit_markdown,
)
from vrf.io_utils import read_jsonl


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit identity rows distorted by relation-consistent decoding."
    )
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--max-cases", type=int, default=50)
    args = parser.parse_args()

    report = audit_decoder_identity_distortion(
        read_jsonl(ROOT / args.benchmark),
        read_jsonl(ROOT / args.predictions),
        max_cases=args.max_cases,
    )

    output_json = ROOT / args.output_json
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    output_md = ROOT / args.output_md
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(
        render_decoder_failure_audit_markdown(report),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "status": report["status"],
                "output_json": args.output_json,
                "output_md": args.output_md,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

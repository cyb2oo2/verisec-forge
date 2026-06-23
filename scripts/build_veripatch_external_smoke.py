from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.external_adapter import build_prediction_template
from vrf.io_utils import read_jsonl, write_json, write_jsonl


def select_smoke_rows(rows: list[dict], *, pairs: int) -> list[dict]:
    cluster_ids = []
    seen = set()
    for row in sorted(rows, key=lambda item: (str(item["cluster_id"]), str(item["id"]))):
        cluster_id = str(row["cluster_id"])
        if cluster_id not in seen:
            seen.add(cluster_id)
            cluster_ids.append(cluster_id)
    selected = set(cluster_ids[:pairs])
    return [
        row
        for row in rows
        if str(row["cluster_id"]) in selected
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the 30-pair VeriPatch-RR external smoke artifact."
    )
    parser.add_argument(
        "--input",
        default="data/processed/secure_code_veripatch_rr_distilgpt2_runtime1024_representative_core_v1.jsonl",
    )
    parser.add_argument("--pairs", type=int, default=30)
    parser.add_argument(
        "--output",
        default="examples/veripatch_rr_smoke_30.jsonl",
    )
    parser.add_argument(
        "--template-output",
        default="examples/veripatch_rr_smoke_30_predictions_template.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        default="examples/veripatch_rr_smoke_30_summary.json",
    )
    args = parser.parse_args()

    rows = select_smoke_rows(read_jsonl(ROOT / args.input), pairs=args.pairs)
    template = build_prediction_template(rows)
    write_jsonl(ROOT / args.output, rows)
    write_jsonl(ROOT / args.template_output, template)
    summary = {
        "status": "ok",
        "source": args.input.replace("\\", "/"),
        "benchmark": args.output.replace("\\", "/"),
        "prediction_template": args.template_output.replace("\\", "/"),
        "pairs": len({str(row["cluster_id"]) for row in rows}),
        "rows": len(rows),
        "templates": sorted({str(row["transformation_template"]) for row in rows}),
        "claim_boundary": (
            "This smoke artifact is a small external-adapter sanity check "
            "using distilgpt2 runtime accounting. It is not tokenizer-neutral "
            "and must not be used for full claims about another model's "
            "runtime visibility. Full-scale model claims require "
            "model-specific runtime materialization and the retained "
            "VeriPatch-RR reports."
        ),
    }
    write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

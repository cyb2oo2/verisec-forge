from __future__ import annotations

import argparse
import json

from build_primevul_evidence_scorer_dataset import build_text
from vrf.io_utils import read_jsonl, write_jsonl


def main() -> None:
    parser = argparse.ArgumentParser(description="Rewrite an existing support-scorer JSONL with a different input mode.")
    parser.add_argument("--input", required=True, help="Existing support-scorer JSONL")
    parser.add_argument("--output", required=True, help="Rewritten support-scorer JSONL")
    parser.add_argument(
        "--input-mode",
        choices=["full", "no_probability", "probability_only", "code_only", "heuristic_only"],
        required=True,
    )
    args = parser.parse_args()

    rows_out: list[dict[str, object]] = []
    for row in read_jsonl(args.input):
        code = str(row.get("code") or "")
        language = str(row.get("language") or "c")
        probability = float(row.get("detector_probability", 0.0))
        label_mode = str(row.get("support_scorer_label_mode", "heuristic_support"))
        text = build_text(
            code=code,
            language=language,
            probability=probability,
            input_mode=args.input_mode,
            label_mode=label_mode,
        )
        rewritten = dict(row)
        rewritten["text"] = text
        rewritten["prompt"] = text
        rewritten["support_scorer_input_mode"] = args.input_mode
        rows_out.append(rewritten)

    write_jsonl(args.output, rows_out)
    positives = sum(bool(row["has_vulnerability"]) for row in rows_out)
    payload = {
        "rows": len(rows_out),
        "supported_positive_rows": positives,
        "negative_rows": len(rows_out) - positives,
        "input": args.input,
        "output": args.output,
        "input_mode": args.input_mode,
    }
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()

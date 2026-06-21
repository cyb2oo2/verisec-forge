from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_jsonl

LABEL_RE = re.compile(r"\b(A_RISKIER|B_RISKIER|INSUFFICIENT_CONTEXT)\b", re.I)


def parse_label(text: str) -> str:
    matches = LABEL_RE.findall(text or "")
    if len(matches) != 1:
        return "INVALID"
    return matches[0].upper()


def convert_raw_generations(raw_rows: list[dict]) -> list[dict]:
    predictions = []
    for row in raw_rows:
        raw_text = str(
            row.get("generated_text")
            or row.get("text")
            or row.get("output")
            or row.get("prediction")
            or ""
        )
        label = parse_label(raw_text)
        predictions.append(
            {
                "id": row["id"],
                "predicted_riskier_side": label,
                "confidence": row.get("confidence"),
                "model_id": row.get("model_id", "generative_instruction_judge"),
                "supports_abstention": True,
                "raw_output": raw_text,
            }
        )
    return predictions


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Convert strict generative judge outputs into VeriPatch-RR "
            "prediction JSONL. Model invocation is intentionally external so "
            "the fixed prompt can be run by any provider or local runtime."
        )
    )
    parser.add_argument("--raw-generations", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--prompt-contract-output",
        default="reports/GENERATIVE_JUDGE_PROMPT_CONTRACT.md",
    )
    args = parser.parse_args()

    predictions = convert_raw_generations(read_jsonl(args.raw_generations))
    write_jsonl(args.output, predictions)
    Path(args.prompt_contract_output).write_text(
        "\n".join(
            [
                "# Generative Instruction Judge Contract",
                "",
                "For each VeriPatch-RR prompt, output exactly one label:",
                "",
                "```text",
                "A_RISKIER",
                "B_RISKIER",
                "INSUFFICIENT_CONTEXT",
                "```",
                "",
                "No explanation, JSON, markdown, or extra text is allowed in the scored output.",
            ]
        ),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": "ok",
                "rows": len(predictions),
                "invalid_rows": sum(
                    row["predicted_riskier_side"] == "INVALID"
                    for row in predictions
                ),
                "output": args.output,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

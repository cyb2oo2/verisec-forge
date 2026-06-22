from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_jsonl

LABEL_RE = re.compile(
    r"^\s*(A_RISKIER|B_RISKIER|INSUFFICIENT_CONTEXT)\s*$", re.I
)
DEFAULT_TEMPLATES = (
    "canonical_pair_renderer_v2",
    "canonical_renderer_swap_v2",
    "length_only_end_numbered_comments_v2",
)


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


def filter_runtime_rows(
    rows: list[dict],
    *,
    suite: str,
    templates: set[str],
    limit: int | None = None,
) -> list[dict]:
    selected = [
        row
        for row in rows
        if str(row.get("sampling_suite")) == suite
        and str(row.get("transformation_template")) in templates
    ]
    selected.sort(key=lambda row: (str(row["pair_key"]), str(row["id"])))
    return selected[:limit] if limit is not None else selected


def build_prompt(text: str) -> str:
    return text


def generate_raw_outputs(
    rows: list[dict],
    *,
    model_id: str,
    batch_size: int,
    max_new_tokens: int,
    local_files_only: bool,
) -> list[dict]:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(
        model_id, local_files_only=local_files_only
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "left"
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        local_files_only=local_files_only,
        torch_dtype=(
            torch.bfloat16 if torch.cuda.is_available() else torch.float32
        ),
    )
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()

    raw_rows = []
    started = time.perf_counter()
    for start in range(0, len(rows), batch_size):
        batch = rows[start : start + batch_size]
        prompts = [build_prompt(str(row["text"])) for row in batch]
        tokenized = tokenizer(
            prompts,
            truncation=True,
            max_length=int(batch[0]["runtime_accounting"]["max_length"]),
            padding=True,
            return_tensors="pt",
        )
        tokenized = {key: value.to(device) for key, value in tokenized.items()}
        prompt_length = tokenized["input_ids"].shape[1]
        with torch.inference_mode():
            outputs = model.generate(
                **tokenized,
                max_new_tokens=max_new_tokens,
                do_sample=False,
                pad_token_id=tokenizer.pad_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )
        for row, output in zip(batch, outputs, strict=True):
            generated = tokenizer.decode(
                output[prompt_length:],
                skip_special_tokens=True,
            ).strip()
            raw_rows.append(
                {
                    "id": row["id"],
                    "generated_text": generated,
                    "model_id": model_id,
                }
            )
        processed = min(start + batch_size, len(rows))
        elapsed = max(time.perf_counter() - started, 1e-9)
        print(
            f"generative judge progress {processed}/{len(rows)} "
            f"rate={processed / elapsed:.2f} rows/s",
            flush=True,
        )
    return raw_rows


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Convert strict generative judge outputs into VeriPatch-RR "
            "prediction JSONL. Model invocation is intentionally external so "
            "the fixed prompt can be run by any provider or local runtime."
        )
    )
    parser.add_argument("--raw-generations")
    parser.add_argument("--runtime")
    parser.add_argument("--model-id")
    parser.add_argument("--raw-output")
    parser.add_argument("--filtered-runtime-output")
    parser.add_argument("--output", required=True)
    parser.add_argument("--suite", default="representative")
    parser.add_argument(
        "--templates",
        nargs="*",
        default=list(DEFAULT_TEMPLATES),
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--max-new-tokens", type=int, default=8)
    parser.add_argument("--local-files-only", action="store_true")
    parser.add_argument(
        "--prompt-contract-output",
        default="reports/GENERATIVE_JUDGE_PROMPT_CONTRACT.md",
    )
    args = parser.parse_args()

    if args.raw_generations:
        raw_rows = read_jsonl(args.raw_generations)
    else:
        if not args.runtime or not args.model_id or not args.raw_output:
            parser.error(
                "provide --raw-generations, or provide --runtime, "
                "--model-id, and --raw-output"
            )
        runtime_rows = filter_runtime_rows(
            read_jsonl(args.runtime),
            suite=args.suite,
            templates=set(args.templates),
            limit=args.limit,
        )
        if args.filtered_runtime_output:
            write_jsonl(args.filtered_runtime_output, runtime_rows)
        raw_rows = generate_raw_outputs(
            runtime_rows,
            model_id=args.model_id,
            batch_size=args.batch_size,
            max_new_tokens=args.max_new_tokens,
            local_files_only=args.local_files_only,
        )
        write_jsonl(args.raw_output, raw_rows)

    predictions = convert_raw_generations(raw_rows)
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
                "",
                "For local causal-LM runs, the scored benchmark text should end with:",
                "",
                "```text",
                "Final answer (one label only):",
                "```",
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

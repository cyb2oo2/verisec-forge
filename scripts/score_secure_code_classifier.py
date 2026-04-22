from __future__ import annotations

import argparse
import json
from pathlib import Path

from vrf.io_utils import read_jsonl, write_jsonl
from vrf.training_common import load_tokenizer, optional_import_train_stack, pretrained_kwargs, resolve_local_model_source


def main() -> None:
    parser = argparse.ArgumentParser(description="Score a secure-code dataset with a trained classifier checkpoint.")
    parser.add_argument("--model", required=True, help="Classifier checkpoint path or model name")
    parser.add_argument("--dataset", required=True, help="Input secure-code JSONL dataset")
    parser.add_argument("--output", required=True, help="Output probabilities JSONL path")
    parser.add_argument("--text-field", default="code")
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-length", type=int, default=1024)
    parser.add_argument("--local-files-only", action="store_true")
    args = parser.parse_args()

    stack = optional_import_train_stack()
    torch = stack["torch"]
    transformers = stack["transformers"]
    try:
        from peft import AutoPeftModelForSequenceClassification
    except ImportError as exc:
        raise RuntimeError("peft is required to score classifier checkpoints") from exc

    tokenizer = load_tokenizer(
        transformers_module=transformers,
        model_name=args.model,
        local_files_only=args.local_files_only,
    )
    model_source = resolve_local_model_source(args.model, args.local_files_only)
    adapter_config_path = Path(model_source) / "adapter_config.json"
    if adapter_config_path.exists():
        model = AutoPeftModelForSequenceClassification.from_pretrained(
            model_source,
            **pretrained_kwargs(args.local_files_only),
        )
    else:
        model = transformers.AutoModelForSequenceClassification.from_pretrained(
            model_source,
            **pretrained_kwargs(args.local_files_only),
        )
    model.config.pad_token_id = tokenizer.pad_token_id
    model.eval()
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device)

    rows = read_jsonl(args.dataset)
    rows_out: list[dict[str, object]] = []
    for start in range(0, len(rows), args.batch_size):
        batch = rows[start : start + args.batch_size]
        texts = [str(row.get(args.text_field) or row.get("prompt") or "") for row in batch]
        encoded = tokenizer(
            texts,
            truncation=True,
            max_length=args.max_length,
            padding=True,
            return_tensors="pt",
        )
        encoded = {key: value.to(device) for key, value in encoded.items()}
        with torch.no_grad():
            logits = model(**encoded).logits
            probs = torch.softmax(logits, dim=-1)[:, 1].detach().cpu().tolist()
        for row, prob in zip(batch, probs, strict=False):
            rows_out.append(
                {
                    "id": row["id"],
                    "gold": int(bool(row.get("has_vulnerability"))),
                    "vuln_probability": float(prob),
                    "pred": int(prob >= 0.5),
                }
            )

    write_jsonl(args.output, rows_out)
    print(json.dumps({"rows": len(rows_out), "output": args.output}, indent=2))


if __name__ == "__main__":
    main()

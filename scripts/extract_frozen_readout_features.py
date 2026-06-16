from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.frozen_readout_control import (
    normalize_hf_model_source,
    pool_frozen_representations,
)
from vrf.io_utils import read_jsonl, write_json
from vrf.readout_classifier import tokenize_readout_batch
from vrf.reproducibility import sha256_file


def metadata_for(split: str, row: dict[str, Any]) -> dict[str, Any]:
    if split == "train":
        return {
            "id": str(row["id"]),
            "pair_key": str(row["pair_key"]),
            "label": int(row["label"]),
        }
    return {
        "id": str(row["id"]),
        "dataset": str(row["dataset"]),
        "pair_key": str(row["pair_key"]),
        "audit_variant": str(row["audit_variant"]),
        "gold_riskier_side": str(row["gold_riskier_side"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cache matched readout features from one frozen backbone."
    )
    parser.add_argument(
        "--config",
        default=(
            "configs/"
            "research_frozen_backbone_readout_control_qwen15b_v1.json"
        ),
    )
    parser.add_argument("--split", choices=("train", "confirm"), required=True)
    parser.add_argument("--output")
    parser.add_argument("--max-rows", type=int)
    parser.add_argument("--batch-size", type=int)
    args = parser.parse_args()

    import torch
    from peft import AutoPeftModelForSequenceClassification
    from transformers import AutoTokenizer

    config = json.loads((ROOT / args.config).read_text(encoding="utf-8"))
    dataset_key = f"{args.split}_dataset"
    cache_key = f"{args.split}_cache"
    max_length = int(config[f"{args.split}_max_length"])
    rows = read_jsonl(ROOT / config[dataset_key])
    if args.max_rows:
        rows = rows[: args.max_rows]
    rows.sort(
        key=lambda row: (
            len(str(row["text"])),
            str(row["id"]),
        )
    )

    checkpoint = ROOT / config["frozen_checkpoint"]
    tokenizer = AutoTokenizer.from_pretrained(
        checkpoint,
        local_files_only=True,
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    peft_model = AutoPeftModelForSequenceClassification.from_pretrained(
        checkpoint,
        local_files_only=True,
        dtype=torch.bfloat16,
        is_trainable=False,
    )
    peft_model.config.pad_token_id = tokenizer.pad_token_id
    peft_model.to("cuda")
    peft_model.eval()
    decoder = peft_model.base_model.model.model
    batch_size = int(args.batch_size or config["feature_batch_size"])

    features: dict[str, list[Any]] = {
        "terminal": [],
        "mean": [],
        "changed_hunk": [],
    }
    fallback_flags: list[bool] = []
    metadata = []
    started = time.perf_counter()
    for start in range(0, len(rows), batch_size):
        batch = rows[start : start + batch_size]
        encoded = tokenize_readout_batch(
            tokenizer,
            [str(row["text"]) for row in batch],
            readout_type="changed_hunk",
            max_length=max_length,
        )
        pooling_mask = encoded.pop("pooling_mask")
        model_inputs = {
            key: value.to("cuda", non_blocking=True)
            for key, value in encoded.items()
        }
        with torch.inference_mode(), torch.autocast(
            device_type="cuda",
            dtype=torch.bfloat16,
        ):
            hidden = decoder(
                input_ids=model_inputs["input_ids"],
                attention_mask=model_inputs["attention_mask"],
                use_cache=False,
            ).last_hidden_state
            pooled, fallback = pool_frozen_representations(
                hidden,
                input_ids=model_inputs["input_ids"],
                attention_mask=model_inputs["attention_mask"],
                pooling_mask=pooling_mask,
                pad_token_id=int(tokenizer.pad_token_id),
            )
        for readout, tensor in pooled.items():
            features[readout].append(tensor.to("cpu", dtype=torch.float16))
        fallback_flags.extend(bool(value) for value in fallback.cpu().tolist())
        metadata.extend(metadata_for(args.split, row) for row in batch)
        processed = min(start + batch_size, len(rows))
        if start == 0 or processed % 200 == 0 or processed == len(rows):
            elapsed = max(time.perf_counter() - started, 1e-9)
            print(
                f"{args.split}: {processed}/{len(rows)} "
                f"rate={processed / elapsed:.2f} rows/s",
                flush=True,
            )

    adapter_path = checkpoint / "adapter_model.safetensors"
    base_model = normalize_hf_model_source(
        peft_model.peft_config["default"].base_model_name_or_path
    )
    payload = {
        "schema_version": 1,
        "split": args.split,
        "frozen_checkpoint": config["frozen_checkpoint"],
        "adapter_sha256": (
            sha256_file(adapter_path) if adapter_path.exists() else None
        ),
        "base_model_id": base_model["model_id"],
        "base_model_revision": base_model["revision"],
        "max_length": max_length,
        "hidden_size": int(peft_model.config.hidden_size),
        "metadata": metadata,
        "changed_hunk_fallback": torch.tensor(
            fallback_flags,
            dtype=torch.bool,
        ),
        "features": {
            readout: torch.cat(parts, dim=0)
            for readout, parts in features.items()
        },
    }
    output = ROOT / (args.output or config[cache_key])
    output.parent.mkdir(parents=True, exist_ok=True)
    torch.save(payload, output)
    report = {
        "status": "ok",
        "split": args.split,
        "output": str(output.relative_to(ROOT)),
        "output_sha256": sha256_file(output),
        "output_bytes": output.stat().st_size,
        "rows": len(metadata),
        "hidden_size": payload["hidden_size"],
        "feature_dtype": "float16",
        "readouts": ["terminal", "mean", "changed_hunk"],
        "fallback_rows": sum(fallback_flags),
        "frozen_checkpoint": config["frozen_checkpoint"],
        "adapter_sha256": payload["adapter_sha256"],
        "base_model_revision": payload["base_model_revision"],
        "base_model_id": payload["base_model_id"],
        "tokenizer": config["frozen_checkpoint"],
        "max_length": max_length,
        "batch_size": batch_size,
        "elapsed_seconds": time.perf_counter() - started,
        "environment": {
            "gpu": torch.cuda.get_device_name(0),
            "torch": torch.__version__,
            "transformers": __import__("transformers").__version__,
            "peft": __import__("peft").__version__,
        },
        "claim_boundary": (
            "The cache contains frozen hidden representations and metadata, "
            "not model predictions or a robustness conclusion."
        ),
    }
    if not args.max_rows and not args.output:
        write_json(ROOT / config[f"{args.split}_cache_report"], report)
    print(json.dumps(report, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

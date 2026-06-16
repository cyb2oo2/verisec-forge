from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.frozen_readout_control import (
    FROZEN_READOUT_TYPES,
    complete_pair_indices,
    pairwise_head_loss,
    state_dict_sha256,
)
from vrf.io_utils import write_json


def load_cache(path: Path) -> dict[str, Any]:
    import torch

    return torch.load(path, map_location="cpu", weights_only=False)


def validate_caches(train: dict[str, Any], confirm: dict[str, Any]) -> None:
    for key in (
        "frozen_checkpoint",
        "adapter_sha256",
        "base_model_id",
        "base_model_revision",
        "hidden_size",
    ):
        if train[key] != confirm[key]:
            raise ValueError(f"feature cache mismatch for {key}")
    for cache in (train, confirm):
        rows = len(cache["metadata"])
        for readout in FROZEN_READOUT_TYPES:
            if cache["features"][readout].shape[0] != rows:
                raise ValueError(f"{readout} feature row mismatch")


def train_head(
    train_cache: dict[str, Any],
    *,
    readout: str,
    seed: int,
    initial_state: dict[str, Any],
    orders: list[Any],
    config: dict[str, Any],
) -> tuple[Any, dict[str, Any]]:
    import torch

    head = torch.nn.Linear(int(train_cache["hidden_size"]), 2).to("cuda")
    head.load_state_dict(copy.deepcopy(initial_state))
    optimizer = torch.optim.AdamW(
        head.parameters(),
        lr=float(config["training"]["learning_rate"]),
        weight_decay=float(config["training"]["weight_decay"]),
    )
    pair_indices = complete_pair_indices(train_cache["metadata"])
    features = train_cache["features"][readout]
    batch_size = int(config["training"]["pair_batch_size"])
    history = []
    head.train()
    for epoch, order in enumerate(orders, start=1):
        total_loss = 0.0
        for start in range(0, len(order), batch_size):
            selected = order[start : start + batch_size].tolist()
            flat_indices = [
                index
                for pair_position in selected
                for index in pair_indices[pair_position]
            ]
            x = features[flat_indices].to(
                "cuda",
                dtype=torch.float32,
                non_blocking=True,
            )
            logits = head(x).reshape(len(selected), 2, 2)
            loss, parts = pairwise_head_loss(
                logits,
                margin=float(config["loss"]["margin"]),
                margin_weight=float(config["loss"]["margin_weight"]),
                complement_weight=float(config["loss"]["complement_weight"]),
            )
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            optimizer.step()
            total_loss += float(loss.detach()) * len(selected)
        history.append(total_loss / len(pair_indices))
        if (
            epoch == 1
            or epoch % int(config["training"]["logging_epochs"]) == 0
            or epoch == len(orders)
        ):
            print(
                f"seed={seed} readout={readout} epoch={epoch} "
                f"loss={history[-1]:.5f}",
                flush=True,
            )
    return head, {
        "epochs": len(orders),
        "steps": sum(
            (len(order) + batch_size - 1) // batch_size for order in orders
        ),
        "loss_history": history,
    }


def predict_confirm(
    head: Any,
    cache: dict[str, Any],
    *,
    readout: str,
) -> list[dict[str, Any]]:
    import torch

    head.eval()
    features = cache["features"][readout]
    rows = []
    with torch.inference_mode():
        for start in range(0, len(features), 256):
            logits = head(
                features[start : start + 256].to(
                    "cuda",
                    dtype=torch.float32,
                )
            )
            probabilities = logits.softmax(dim=-1).cpu().tolist()
            for metadata, probs, fallback in zip(
                cache["metadata"][start : start + 256],
                probabilities,
                cache["changed_hunk_fallback"][start : start + 256].tolist(),
                strict=True,
            ):
                rows.append(
                    {
                        "id": metadata["id"],
                        "predicted_riskier_side": (
                            "A" if probs[0] >= probs[1] else "B"
                        ),
                        "probability_a": float(probs[0]),
                        "probability_b": float(probs[1]),
                        "confidence": float(max(probs)),
                        "model_id": (
                            "frozen_backbone_readout_control_"
                            f"{readout}"
                        ),
                        "readout_type": readout,
                        "pooling_fallback": (
                            bool(fallback)
                            if readout == "changed_hunk"
                            else False
                        ),
                        "supports_abstention": False,
                    }
                )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Train matched linear heads over frozen readout features."
    )
    parser.add_argument(
        "--config",
        default=(
            "configs/"
            "research_frozen_backbone_readout_control_qwen15b_v1.json"
        ),
    )
    parser.add_argument("--train-cache")
    parser.add_argument("--confirm-cache")
    parser.add_argument("--seeds", nargs="+", type=int)
    parser.add_argument("--readouts", nargs="+", choices=FROZEN_READOUT_TYPES)
    args = parser.parse_args()

    import torch

    config = json.loads((ROOT / args.config).read_text(encoding="utf-8"))
    train_cache = load_cache(
        ROOT / (args.train_cache or config["train_cache"])
    )
    confirm_cache = load_cache(
        ROOT / (args.confirm_cache or config["confirm_cache"])
    )
    validate_caches(train_cache, confirm_cache)
    pair_count = len(complete_pair_indices(train_cache["metadata"]))
    seeds = args.seeds or [int(seed) for seed in config["seeds"]]
    readouts = args.readouts or list(FROZEN_READOUT_TYPES)

    for seed in seeds:
        torch.manual_seed(seed)
        prototype = torch.nn.Linear(int(train_cache["hidden_size"]), 2)
        initial_state = copy.deepcopy(prototype.state_dict())
        initial_head_sha256 = state_dict_sha256(initial_state)
        generator = torch.Generator(device="cpu").manual_seed(seed)
        orders = [
            torch.randperm(pair_count, generator=generator)
            for _ in range(int(config["training"]["num_train_epochs"]))
        ]
        for readout in readouts:
            head, training = train_head(
                train_cache,
                readout=readout,
                seed=seed,
                initial_state=initial_state,
                orders=orders,
                config=config,
            )
            predictions = predict_confirm(
                head,
                confirm_cache,
                readout=readout,
            )
            values = {
                "readout": readout,
                "seed": seed,
            }
            predictions_path = ROOT / config[
                "predictions_template"
            ].format(**values)
            predictions_path.parent.mkdir(parents=True, exist_ok=True)
            with predictions_path.open("w", encoding="utf-8") as handle:
                for row in predictions:
                    handle.write(json.dumps(row) + "\n")
            head_path = ROOT / config["head_template"].format(**values)
            head_path.parent.mkdir(parents=True, exist_ok=True)
            torch.save(head.state_dict(), head_path)
            final_head_sha256 = state_dict_sha256(head.state_dict())
            report = {
                "status": "ok",
                "method": "matched_linear_head_over_frozen_backbone",
                "frozen_checkpoint": train_cache["frozen_checkpoint"],
                "adapter_sha256": train_cache["adapter_sha256"],
                "base_model_revision": train_cache["base_model_revision"],
                "base_model_id": train_cache["base_model_id"],
                "readout": readout,
                "seed": seed,
                "hidden_size": int(train_cache["hidden_size"]),
                "initial_head_sha256": initial_head_sha256,
                "final_head_sha256": final_head_sha256,
                "train_pairs": pair_count,
                "confirm_rows": len(confirm_cache["metadata"]),
                "training": training,
                "contract": {
                    "head": "Linear(hidden_size, 2)",
                    "loss": config["loss"],
                    "optimizer": "AdamW",
                    **config["training"],
                },
                "environment": {
                    "gpu": torch.cuda.get_device_name(0),
                    "torch": torch.__version__,
                },
                "claim_boundary": (
                    "Only the matched linear head is trained. The backbone "
                    "and LoRA representation are frozen and shared."
                ),
            }
            write_json(
                ROOT / config["training_report_template"].format(**values),
                report,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

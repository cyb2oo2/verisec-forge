"""How much net-polarity information survives in a frozen encoder's representation?

Settles the open question left by ``reports/POLARITY_ADVERSARIAL_V1.md``: the
gradient-reversal adversary's auxiliary head plateaued at ~0.586 polarity
accuracy, which is consistent with either

1. the adversary being too weak to find polarity the encoder still carries, or
2. polarity already being absent / inseparable from the task signal.

A *strong* probe trained on a frozen encoder distinguishes these. If a large MLP
recovers polarity at ~0.85-0.90+, reading 1 holds and a stronger adversary is
worth building. If even a strong probe stays near chance, reading 2 holds.

The encoder is never updated: representations are extracted under ``no_grad`` and
cached, then probes are fit on the cached vectors. Probes are trained on a
pair-disjoint split so no pair contributes to both fit and validation.

Pooling matches the relational head: last non-pad position of the final hidden
layer. Polarity is a property of the *pair*, read from the glyph rendering and
sign-flipped for swap renderings, because the prose rendering carries no +/-
lines.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vrf.io_utils import read_jsonl, write_json
from vrf.polarity_control import diff_line_counts
from vrf.gpu_budget import apply_gpu_budget, describe, make_throttle
from vrf.training_common import optional_import_train_stack


def polarity_labels(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Pair-level polarity sign, mirrored for the swap renderings."""

    canonical_net: dict[str, int] = {}
    for row in rows:
        if row["rendering_family"] == "glyph" and row["audit_variant"] == "canonical":
            canonical_net[row["pair_key"]] = diff_line_counts(row["text"])["char_net"]

    labels: dict[str, int] = {}
    for row in rows:
        net = canonical_net.get(row["pair_key"])
        if net is None or net == 0:
            continue
        swapped = row["audit_variant"].endswith("side_swap")
        value = -net if swapped else net
        labels[row["id"]] = 1 if value > 0 else 0
    return labels


def extract_representations(
    checkpoint: Path, rows: list[dict[str, Any]], *, batch_size: int, load_in_4bit: bool = False
):
    stack = optional_import_train_stack()
    torch = stack["torch"]
    transformers = stack["transformers"]
    from peft import AutoPeftModelForSequenceClassification

    # Cap before the weights load, so the budget bounds the whole run.
    print(describe(apply_gpu_budget(torch)), flush=True)
    throttle = make_throttle()

    tokenizer = transformers.AutoTokenizer.from_pretrained(
        str(checkpoint), local_files_only=True
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    quant_kwargs: dict[str, Any] = {}
    if load_in_4bit:
        # Must match the precision the adapter was trained under: probing a
        # QLoRA checkpoint through dequantised weights would measure a
        # different model than the one the reported accuracies come from.
        quant_kwargs["quantization_config"] = transformers.BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )
    model = AutoPeftModelForSequenceClassification.from_pretrained(
        str(checkpoint),
        local_files_only=True,
        is_trainable=False,
        dtype=torch.bfloat16,
        **quant_kwargs,
    )
    model.config.pad_token_id = tokenizer.pad_token_id
    # from_pretrained leaves the model on CPU; extraction is ~1000x slower there.
    # bitsandbytes already places 4-bit weights on the GPU and rejects .to().
    if torch.cuda.is_available() and not load_in_4bit:
        model.to(torch.device("cuda"))
    model.eval()

    features: list[Any] = []
    ordered = sorted(rows, key=lambda r: str(r["id"]))
    with torch.no_grad():
        for start in range(0, len(ordered), batch_size):
            batch = ordered[start : start + batch_size]
            encoded = tokenizer(
                [str(r["text"]) for r in batch],
                truncation=True,
                max_length=1024,
                padding=True,
                pad_to_multiple_of=8,
                return_tensors="pt",
            ).to(model.device)
            outputs = model(**encoded, output_hidden_states=True)
            last_hidden = outputs.hidden_states[-1]
            lengths = encoded["attention_mask"].sum(dim=1) - 1
            pooled = last_hidden[torch.arange(last_hidden.size(0)), lengths]
            features.append(pooled.float().cpu())
            throttle()
            if start % (batch_size * 50) == 0:
                print(f"  extracted {start + len(batch)}/{len(ordered)}", flush=True)
    return [str(r["id"]) for r in ordered], torch.cat(features, dim=0)


def fit_probe(
    torch,
    train_x,
    train_y,
    val_x,
    val_y,
    *,
    kind: str,
    hidden: int,
    epochs: int,
    seed: int,
):
    torch.manual_seed(seed)
    dim = train_x.shape[1]
    if kind == "linear":
        probe = torch.nn.Linear(dim, 1)
    else:
        probe = torch.nn.Sequential(
            torch.nn.Linear(dim, hidden),
            torch.nn.ReLU(),
            torch.nn.Dropout(0.1),
            torch.nn.Linear(hidden, hidden // 2),
            torch.nn.ReLU(),
            torch.nn.Linear(hidden // 2, 1),
        )
    device = "cuda" if torch.cuda.is_available() else "cpu"
    probe.to(device)
    train_x, train_y = train_x.to(device), train_y.to(device)
    val_x, val_y = val_x.to(device), val_y.to(device)

    # Standardise on train statistics only.
    mean, std = train_x.mean(0, keepdim=True), train_x.std(0, keepdim=True) + 1e-6
    train_x = (train_x - mean) / std
    val_x = (val_x - mean) / std

    optimiser = torch.optim.AdamW(probe.parameters(), lr=1e-3, weight_decay=1e-4)
    curve = []
    best = 0.0
    for epoch in range(epochs):
        probe.train()
        optimiser.zero_grad()
        loss = torch.nn.functional.binary_cross_entropy_with_logits(
            probe(train_x).squeeze(-1), train_y
        )
        loss.backward()
        optimiser.step()
        probe.eval()
        with torch.no_grad():
            train_acc = ((probe(train_x).squeeze(-1) > 0).float() == train_y).float().mean()
            val_acc = ((probe(val_x).squeeze(-1) > 0).float() == val_y).float().mean()
        best = max(best, float(val_acc))
        if epoch % max(1, epochs // 10) == 0 or epoch == epochs - 1:
            curve.append(
                {
                    "epoch": epoch,
                    "loss": round(float(loss), 4),
                    "train_accuracy": round(float(train_acc), 4),
                    "val_accuracy": round(float(val_acc), 4),
                }
            )
    return {"peak_val_accuracy": round(best, 4), "curve": curve}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", action="append", required=True, help="name=path")
    parser.add_argument(
        "--suite",
        type=Path,
        default=ROOT / "data/processed/secure_code_relational_benchmark_v4_runtime1024.jsonl",
    )
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument(
        "--load-in-4bit",
        action="store_true",
        help=(
            "Load backbones as nf4. Required for a 7B on a 12 GB card, and must "
            "match the precision the adapter was trained under."
        ),
    )
    parser.add_argument("--probe-epochs", type=int, default=400)
    parser.add_argument("--hidden", type=int, default=512)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "reports/polarity_probe_diagnostic.json"
    )
    args = parser.parse_args()

    stack = optional_import_train_stack()
    torch = stack["torch"]

    rows = read_jsonl(args.suite)
    labels = polarity_labels(rows)
    usable = [r for r in rows if str(r["id"]) in labels]
    print(f"rows with a defined polarity label: {len(usable)}/{len(rows)}")

    # Pair-disjoint split.
    keys = sorted({str(r["pair_key"]) for r in usable})
    rng = random.Random(args.seed)
    rng.shuffle(keys)
    cut = int(len(keys) * 0.7)
    train_keys = set(keys[:cut])

    payload: dict[str, Any] = {
        "suite": str(args.suite).replace("\\", "/"),
        "pooling": "last non-pad position of the final hidden layer (matches the relational head)",
        "split": {
            "unit": "pair_key",
            "train_pairs": cut,
            "val_pairs": len(keys) - cut,
        },
        "probe_epochs": args.probe_epochs,
        "hidden": args.hidden,
        "checkpoints": {},
    }

    for spec in args.checkpoint:
        name, path = spec.split("=", 1)
        print(f"\n=== extracting representations: {name}")
        ids, features = extract_representations(
            ROOT / path, usable, batch_size=args.batch_size, load_in_4bit=args.load_in_4bit
        )
        index = {row_id: position for position, row_id in enumerate(ids)}
        by_id = {str(r["id"]): r for r in usable}

        entry: dict[str, Any] = {"path": path, "families": {}}
        for family in ("glyph", "prose"):
            selected = [
                row_id
                for row_id in ids
                if by_id[row_id]["rendering_family"] == family
            ]
            train_idx = [
                index[i] for i in selected if str(by_id[i]["pair_key"]) in train_keys
            ]
            val_idx = [
                index[i] for i in selected if str(by_id[i]["pair_key"]) not in train_keys
            ]
            train_x = features[train_idx]
            val_x = features[val_idx]
            train_y = torch.tensor(
                [float(labels[ids[i]]) for i in train_idx], dtype=torch.float32
            )
            val_y = torch.tensor(
                [float(labels[ids[i]]) for i in val_idx], dtype=torch.float32
            )
            family_entry = {
                "train_rows": len(train_idx),
                "val_rows": len(val_idx),
                "val_positive_rate": round(float(val_y.mean()), 4),
            }
            for kind in ("linear", "mlp"):
                family_entry[kind] = fit_probe(
                    torch,
                    train_x,
                    train_y,
                    val_x,
                    val_y,
                    kind=kind,
                    hidden=args.hidden,
                    epochs=args.probe_epochs,
                    seed=args.seed,
                )
                print(
                    f"  {name:22s} {family:5s} {kind:6s} "
                    f"peak val acc = {family_entry[kind]['peak_val_accuracy']:.4f}"
                )
            entry["families"][family] = family_entry
        payload["checkpoints"][name] = entry

    write_json(args.output, payload)
    print(f"\nwrote {args.output}")
    print(f"\n{'checkpoint':28s} {'family':7s} {'linear':>8s} {'mlp':>8s}")
    for name, entry in payload["checkpoints"].items():
        for family, family_entry in entry["families"].items():
            print(
                f"{name:28s} {family:7s} "
                f"{family_entry['linear']['peak_val_accuracy']:>8.4f} "
                f"{family_entry['mlp']['peak_val_accuracy']:>8.4f}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Iterative Nullspace Projection (INLP) of the linear polarity direction.

``reports/POLARITY_PROBE_DIAGNOSTIC.md`` showed net polarity is *linearly*
decodable from the frozen prose-native encoder at up to `0.906`. INLP removes
that linear signal deterministically: fit a linear polarity classifier, project
the representation onto the nullspace of its weight vector, repeat.

Two readouts are evaluated after every round, because they answer different
questions:

* **frozen head** -- the checkpoint's own ``score`` layer applied to the
  projected representation. Measures how much the existing decision *depended*
  on the removed direction.
* **retrained head** -- a fresh antisymmetric readout fit on projected
  *training* representations. Measures whether any other usable signal remains
  once polarity is gone. The frozen head cannot answer this: it has no
  opportunity to rely on anything else.

The antisymmetric decision is linear in the pooled representation. With
``u = W[1] - W[0]`` from the sequence-classification head,
``g(h) = u . h + c`` and the pair score is ``g(h_canonical) - g(h_swap)``,
in which ``c`` cancels. So both readouts reduce to a single vector ``u``, and the
retrained head is logistic regression through the origin on the difference
vectors (augmented with their negations, which is exactly the antisymmetry
constraint).

Nothing is written back to any checkpoint.
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
from vrf.training_common import optional_import_train_stack

CACHE = ROOT / "outputs" / "inlp_representation_cache"


def polarity_sign_map(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Pair-level polarity, read from the glyph rendering, mirrored on swaps."""

    canonical_net: dict[str, int] = {}
    for row in rows:
        if row.get("rendering_family") == "glyph" and row["audit_variant"] == "canonical":
            canonical_net[row["pair_key"]] = diff_line_counts(row["text"])["char_net"]
    out: dict[str, int] = {}
    for row in rows:
        net = canonical_net.get(row["pair_key"])
        if net is None or net == 0:
            continue
        out[row["id"]] = -net if row["audit_variant"].endswith("side_swap") else net
    return out


def extract(checkpoint: Path, rows: list[dict[str, Any]], tag: str, *, batch_size: int):
    stack = optional_import_train_stack()
    torch = stack["torch"]
    transformers = stack["transformers"]
    from peft import AutoPeftModelForSequenceClassification

    CACHE.mkdir(parents=True, exist_ok=True)
    cache_path = CACHE / f"{tag}.pt"
    if cache_path.exists():
        blob = torch.load(cache_path)
        print(f"  loaded cached representations: {cache_path.name}")
        return blob["ids"], blob["features"], blob["u"]

    tokenizer = transformers.AutoTokenizer.from_pretrained(str(checkpoint), local_files_only=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoPeftModelForSequenceClassification.from_pretrained(
        str(checkpoint), local_files_only=True, is_trainable=False, dtype=torch.bfloat16
    )
    model.config.pad_token_id = tokenizer.pad_token_id
    if torch.cuda.is_available():
        model.to(torch.device("cuda"))
    model.eval()

    score_weight = model.base_model.model.score.weight.detach().float().cpu()
    u = (score_weight[1] - score_weight[0]).clone()

    ordered = sorted(rows, key=lambda r: str(r["id"]))
    chunks = []
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
            last = outputs.hidden_states[-1]
            lengths = encoded["attention_mask"].sum(dim=1) - 1
            chunks.append(last[torch.arange(last.size(0)), lengths].float().cpu())
            if start % (batch_size * 200) == 0:
                print(f"  {tag}: {start + len(batch)}/{len(ordered)}", flush=True)
    features = torch.cat(chunks, dim=0)
    ids = [str(r["id"]) for r in ordered]
    torch.save({"ids": ids, "features": features, "u": u}, cache_path)
    return ids, features, u


def fit_linear(torch, x, y, *, epochs: int, seed: int, through_origin: bool = False):
    torch.manual_seed(seed)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    probe = torch.nn.Linear(x.shape[1], 1, bias=not through_origin).to(device)
    x, y = x.to(device), y.to(device)
    optimiser = torch.optim.AdamW(probe.parameters(), lr=1e-3, weight_decay=1e-4)
    for _ in range(epochs):
        optimiser.zero_grad()
        loss = torch.nn.functional.binary_cross_entropy_with_logits(
            probe(x).squeeze(-1), y
        )
        loss.backward()
        optimiser.step()
    return probe


def accuracy_of(torch, probe, x, y) -> float:
    device = next(probe.parameters()).device
    with torch.no_grad():
        predicted = (probe(x.to(device)).squeeze(-1) > 0).float()
        return float((predicted == y.to(device)).float().mean())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--checkpoint",
        default="checkpoints/cls_secure_code_prose_native_pilot_qwen15b_lora_v1",
    )
    parser.add_argument(
        "--eval-suite",
        default="data/processed/secure_code_relational_benchmark_v4_runtime1024.jsonl",
    )
    parser.add_argument(
        "--train-set", default="data/processed/secure_code_prose_native_train_pilot_v2.jsonl"
    )
    parser.add_argument("--rounds", type=int, default=12)
    parser.add_argument("--probe-epochs", type=int, default=400)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--output", default="reports/inlp_polarity_removal.json")
    args = parser.parse_args()

    stack = optional_import_train_stack()
    torch = stack["torch"]

    eval_rows = read_jsonl(ROOT / args.eval_suite)
    train_rows = read_jsonl(ROOT / args.train_set)

    print("extracting evaluation representations")
    eval_ids, eval_x, u0 = extract(
        ROOT / args.checkpoint, eval_rows, "eval_v4", batch_size=args.batch_size
    )
    print("extracting training representations")
    train_ids, train_x, _ = extract(
        ROOT / args.checkpoint, train_rows, "train_prose", batch_size=args.batch_size
    )

    eval_by_id = {str(r["id"]): r for r in eval_rows}
    eval_index = {row_id: i for i, row_id in enumerate(eval_ids)}
    train_index = {row_id: i for i, row_id in enumerate(train_ids)}

    eval_polarity = polarity_sign_map(eval_rows)
    train_polarity = {
        str(r["id"]): int(r.get("net_char_polarity", 0)) for r in train_rows
    }

    # Pair structures for the task metrics.
    families: dict[str, list[tuple[str, str, str, int]]] = {}
    for family, base_variant, swap_variant in (
        ("glyph", "canonical", "side_swap"),
        ("prose", "prose__canonical", "prose__side_swap"),
    ):
        canonical = {
            r["pair_key"]: r
            for r in eval_rows
            if r["rendering_family"] == family and r["audit_variant"] == base_variant
        }
        swap = {
            r["pair_key"]: r
            for r in eval_rows
            if r["rendering_family"] == family and r["audit_variant"] == swap_variant
        }
        entries = []
        for key, base in canonical.items():
            other = swap.get(key)
            if other is None or base["id"] not in eval_polarity:
                continue
            entries.append(
                (
                    str(base["id"]),
                    str(other["id"]),
                    str(base["gold_riskier_side"]),
                    int(eval_polarity[str(base["id"])]),
                )
            )
        families[family] = entries

    # Training pairs for the retrained head: difference vectors.
    train_pairs: dict[str, dict[int, str]] = {}
    for row in train_rows:
        train_pairs.setdefault(str(row["pair_key"]), {})[int(row["label"])] = str(row["id"])
    diff_rows = [
        (sides[1], sides[0]) for sides in train_pairs.values() if set(sides) == {0, 1}
    ]

    # Polarity probe split (pair-disjoint) on the evaluation set.
    keys = sorted({str(r["pair_key"]) for r in eval_rows})
    rng = random.Random(args.seed)
    rng.shuffle(keys)
    probe_train_keys = set(keys[: int(len(keys) * 0.7)])
    probe_train_idx, probe_val_idx = [], []
    for row_id, polarity in eval_polarity.items():
        target = probe_train_idx if str(eval_by_id[row_id]["pair_key"]) in probe_train_keys else probe_val_idx
        target.append((eval_index[row_id], 1.0 if polarity > 0 else 0.0))

    def polarity_probe_accuracy(x):
        tr_x = x[[i for i, _ in probe_train_idx]]
        tr_y = torch.tensor([y for _, y in probe_train_idx])
        va_x = x[[i for i, _ in probe_val_idx]]
        va_y = torch.tensor([y for _, y in probe_val_idx])
        probe = fit_linear(torch, tr_x, tr_y, epochs=args.probe_epochs, seed=args.seed)
        return accuracy_of(torch, probe, va_x, va_y), probe

    def task_metrics(x, u):
        u = u.to(x.device)
        out = {}
        for family, entries in families.items():
            conc_hits = conc_n = disc_hits = disc_n = 0
            correct_total = 0
            for base_id, swap_id, gold, polarity in entries:
                score = float(
                    torch.dot(u, x[eval_index[base_id]] - x[eval_index[swap_id]])
                )
                predicted = "B" if score > 0 else "A"
                hit = int(predicted == gold)
                correct_total += hit
                concordant = (gold == "A" and polarity > 0) or (gold == "B" and polarity < 0)
                if concordant:
                    conc_hits += hit
                    conc_n += 1
                else:
                    disc_hits += hit
                    disc_n += 1
            acc_c = conc_hits / conc_n if conc_n else 0.0
            acc_d = disc_hits / disc_n if disc_n else 0.0
            out[family] = {
                "n_pairs": len(entries),
                "canonical_accuracy": round(correct_total / len(entries), 4),
                "acc_concordant": round(acc_c, 4),
                "acc_discordant": round(acc_d, 4),
                "balanced_delta_vs_control": round(0.5 * acc_c + 0.5 * acc_d - 0.5, 4),
            }
        return out

    def retrain_head(x_train):
        vectors = []
        for vuln_id, safe_id in diff_rows:
            if vuln_id not in train_index or safe_id not in train_index:
                continue
            vectors.append(x_train[train_index[vuln_id]] - x_train[train_index[safe_id]])
        if not vectors:
            return None
        d = torch.stack(vectors)
        # Antisymmetry: each difference and its negation, targets 1 and 0.
        x = torch.cat([d, -d], dim=0)
        y = torch.cat([torch.ones(len(d)), torch.zeros(len(d))])
        probe = fit_linear(
            torch, x, y, epochs=args.probe_epochs, seed=args.seed, through_origin=True
        )
        return probe.weight.detach().squeeze(0).cpu()

    projection = torch.eye(eval_x.shape[1])
    history = []
    current_eval, current_train = eval_x.clone(), train_x.clone()

    for round_index in range(args.rounds + 1):
        probe_accuracy, probe = polarity_probe_accuracy(current_eval)
        frozen = task_metrics(current_eval, u0)
        retrained_u = retrain_head(current_train)
        retrained = task_metrics(current_eval, retrained_u) if retrained_u is not None else None

        entry = {
            "round": round_index,
            "polarity_probe_val_accuracy": round(probe_accuracy, 4),
            "frozen_head": frozen,
            "retrained_head": retrained,
        }
        history.append(entry)
        print(
            f"round {round_index:2d}  polarity_probe={probe_accuracy:.4f}  "
            f"frozen glyph can={frozen['glyph']['canonical_accuracy']:.4f} "
            f"disc={frozen['glyph']['acc_discordant']:.4f}  "
            f"prose can={frozen['prose']['canonical_accuracy']:.4f} "
            f"disc={frozen['prose']['acc_discordant']:.4f}"
            + (
                f"  | retrained glyph can={retrained['glyph']['canonical_accuracy']:.4f} "
                f"disc={retrained['glyph']['acc_discordant']:.4f} "
                f"prose can={retrained['prose']['canonical_accuracy']:.4f} "
                f"disc={retrained['prose']['acc_discordant']:.4f}"
                if retrained
                else ""
            ),
            flush=True,
        )

        if round_index == args.rounds:
            break

        # Project out this round's polarity direction.
        w = probe.weight.detach().squeeze(0).cpu().float()
        w = w / (w.norm() + 1e-9)
        step = torch.eye(len(w)) - torch.outer(w, w)
        projection = step @ projection
        current_eval = current_eval @ step.T
        current_train = current_train @ step.T

    payload = {
        "checkpoint": args.checkpoint,
        "rounds": args.rounds,
        "probe_epochs": args.probe_epochs,
        "readouts": {
            "frozen_head": "the checkpoint's own score layer; measures dependence on the removed direction",
            "retrained_head": "antisymmetric readout refit on projected training representations; measures whether other usable signal remains",
        },
        "history": history,
    }
    write_json(ROOT / args.output, payload)
    print(f"\nwrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

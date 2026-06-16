from __future__ import annotations

from collections import defaultdict
import hashlib
import random
from statistics import mean
from typing import Any


FROZEN_READOUT_TYPES = ("terminal", "mean", "changed_hunk")


def normalize_hf_model_source(source: str) -> dict[str, str | None]:
    normalized = source.replace("\\", "/")
    parts = normalized.split("/")
    model_part = next(
        (part for part in parts if part.startswith("models--")),
        None,
    )
    if model_part is None:
        return {"model_id": source, "revision": None}
    model_id = model_part.removeprefix("models--").replace("--", "/")
    revision = None
    if "snapshots" in parts:
        index = parts.index("snapshots")
        if index + 1 < len(parts):
            revision = parts[index + 1]
    return {"model_id": model_id, "revision": revision}


def pool_frozen_representations(
    hidden: Any,
    *,
    input_ids: Any,
    attention_mask: Any,
    pooling_mask: Any,
    pad_token_id: int,
) -> tuple[dict[str, Any], Any]:
    import torch

    non_pad = (input_ids != pad_token_id).to(hidden.device, torch.int32)
    indices = torch.arange(
        input_ids.shape[-1],
        device=hidden.device,
        dtype=torch.int32,
    )
    last = (indices * non_pad).argmax(-1)
    terminal = hidden[
        torch.arange(hidden.shape[0], device=hidden.device),
        last,
    ]
    attention_weights = attention_mask.to(hidden.dtype).unsqueeze(-1)
    mean = (hidden * attention_weights).sum(dim=1) / attention_weights.sum(
        dim=1
    ).clamp_min(1.0)

    hunk_mask = pooling_mask.to(hidden.device) * attention_mask
    fallback = hunk_mask.sum(dim=1) == 0
    if fallback.any():
        hunk_mask = hunk_mask.clone()
        hunk_mask[fallback] = attention_mask[fallback]
    hunk_weights = hunk_mask.to(hidden.dtype).unsqueeze(-1)
    changed_hunk = (hidden * hunk_weights).sum(dim=1) / hunk_weights.sum(
        dim=1
    ).clamp_min(1.0)
    return {
        "terminal": terminal,
        "mean": mean,
        "changed_hunk": changed_hunk,
    }, fallback


def complete_pair_indices(
    metadata: list[dict[str, Any]],
) -> list[tuple[int, int]]:
    grouped: dict[str, dict[int, int]] = defaultdict(dict)
    for index, row in enumerate(metadata):
        grouped[str(row["pair_key"])][int(row["label"])] = index
    return [
        (sides[0], sides[1])
        for _, sides in sorted(grouped.items())
        if set(sides) == {0, 1}
    ]


def pairwise_head_loss(
    logits: Any,
    *,
    margin: float,
    margin_weight: float,
    complement_weight: float,
) -> tuple[Any, dict[str, Any]]:
    import torch

    labels = torch.tensor(
        [[0, 1]] * logits.shape[0],
        device=logits.device,
        dtype=torch.long,
    )
    classification = torch.nn.functional.cross_entropy(
        logits.reshape(-1, 2),
        labels.reshape(-1),
    )
    vulnerable_scores = logits[:, :, 1]
    margin_loss = torch.relu(
        margin - (vulnerable_scores[:, 1] - vulnerable_scores[:, 0])
    ).mean()
    probabilities = logits.softmax(dim=-1)[:, :, 1]
    complement = ((probabilities.sum(dim=1) - 1.0) ** 2).mean()
    loss = (
        classification
        + margin_weight * margin_loss
        + complement_weight * complement
    )
    return loss, {
        "classification": classification.detach(),
        "margin": margin_loss.detach(),
        "complement": complement.detach(),
    }


def state_dict_sha256(state_dict: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    for key in sorted(state_dict):
        tensor = state_dict[key].detach().cpu().contiguous()
        digest.update(key.encode("utf-8"))
        digest.update(str(tensor.dtype).encode("ascii"))
        digest.update(str(tuple(tensor.shape)).encode("ascii"))
        digest.update(tensor.numpy().tobytes())
    return digest.hexdigest()


def margin_matched_comparison(
    control_records: list[dict[str, Any]],
    candidate_records: list[dict[str, Any]],
    *,
    tolerance: float = 0.05,
    iterations: int = 5000,
    seed: int = 20260614,
) -> dict[str, Any]:
    control = {
        (str(row["dataset"]), str(row["pair_key"])): row
        for row in control_records
    }
    candidate = {
        (str(row["dataset"]), str(row["pair_key"])): row
        for row in candidate_records
    }
    if control.keys() != candidate.keys():
        raise ValueError("margin-matched records must use identical pair keys")
    matched = [
        (control[key], candidate[key])
        for key in sorted(control)
        if abs(
            float(control[key]["canonical_margin"])
            - float(candidate[key]["canonical_margin"])
        )
        <= tolerance
        and any(control[key]["suffix_visible"].values())
        and any(candidate[key]["suffix_visible"].values())
    ]
    if not matched:
        return {
            "pairs": 0,
            "coverage": 0.0,
            "tolerance": tolerance,
            "macro_suffix_consistency_delta": None,
        }

    def suffix_value(row: dict[str, Any]) -> float:
        values = [
            float(row["suffix_relations"][name])
            for name, visible in row["suffix_visible"].items()
            if visible
        ]
        return mean(values)

    deltas = [
        suffix_value(candidate_row) - suffix_value(control_row)
        for control_row, candidate_row in matched
    ]
    rng = random.Random(seed)
    samples = [
        mean(deltas[rng.randrange(len(deltas))] for _ in deltas)
        for _ in range(iterations)
    ]
    samples.sort()
    return {
        "pairs": len(matched),
        "coverage": len(matched) / len(control),
        "tolerance": tolerance,
        "macro_suffix_consistency_delta": {
            "estimate": mean(deltas),
            "ci95": [
                samples[int(0.025 * (len(samples) - 1))],
                samples[int(0.975 * (len(samples) - 1))],
            ],
        },
    }

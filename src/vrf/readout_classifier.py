from __future__ import annotations

from dataclasses import dataclass
from typing import Any


READOUT_TYPES = (
    "terminal",
    "first_token",
    "mean",
    "changed_hunk",
    "fixed_terminal_anchor",
)
DEFAULT_TERMINAL_ANCHOR = "\nTask complete. Classify Side A or Side B."


def changed_line_spans(text: str) -> list[tuple[int, int]]:
    spans = []
    offset = 0
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        if (
            content.startswith(("+", "-"))
            and not content.startswith(("+++", "---"))
        ):
            spans.append((offset, offset + len(content)))
        offset += len(line)
    return spans


def pooling_mask_from_offsets(
    offsets: list[tuple[int, int]],
    spans: list[tuple[int, int]],
) -> list[int]:
    return [
        int(
            token_end > token_start
            and any(
                token_start < span_end and token_end > span_start
                for span_start, span_end in spans
            )
        )
        for token_start, token_end in offsets
    ]


def tokenize_readout_batch(
    tokenizer: Any,
    texts: list[str],
    *,
    readout_type: str,
    max_length: int,
    pad_to_multiple_of: int | None = 8,
    return_tensors: str = "pt",
    terminal_anchor: str = DEFAULT_TERMINAL_ANCHOR,
) -> dict[str, Any]:
    if readout_type not in READOUT_TYPES:
        raise ValueError(f"Unsupported readout type: {readout_type}")

    rendered = texts
    pooling_masks = None
    if readout_type == "fixed_terminal_anchor":
        anchor_ids = tokenizer(
            terminal_anchor,
            add_special_tokens=False,
        )["input_ids"]
        if len(anchor_ids) >= max_length:
            raise ValueError("terminal anchor consumes the complete context")
        bodies = tokenizer(
            texts,
            truncation=True,
            max_length=max_length - len(anchor_ids),
            padding=False,
            add_special_tokens=True,
        )["input_ids"]
        rendered_ids = [body + anchor_ids for body in bodies]
        return tokenizer.pad(
            {"input_ids": rendered_ids},
            padding=True,
            pad_to_multiple_of=pad_to_multiple_of,
            return_tensors=return_tensors,
        )

    request_offsets = readout_type == "changed_hunk"
    encoded = tokenizer(
        rendered,
        truncation=True,
        max_length=max_length,
        padding=True,
        pad_to_multiple_of=pad_to_multiple_of,
        return_offsets_mapping=request_offsets,
        return_tensors=return_tensors,
    )
    if request_offsets:
        offsets = encoded.pop("offset_mapping").tolist()
        pooling_masks = [
            pooling_mask_from_offsets(row_offsets, changed_line_spans(text))
            for row_offsets, text in zip(offsets, texts, strict=True)
        ]
        import torch

        encoded["pooling_mask"] = torch.tensor(
            pooling_masks,
            dtype=torch.long,
        )
    return encoded


@dataclass
class ReadoutOutput:
    logits: Any


def build_readout_classifier(
    peft_model: Any,
    *,
    readout_type: str,
) -> Any:
    import torch

    if readout_type not in READOUT_TYPES:
        raise ValueError(f"Unsupported readout type: {readout_type}")

    class ReadoutClassifier(torch.nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.peft_model = peft_model
            self.readout_type = readout_type
            self.config = peft_model.config

        def enable_input_require_grads(self) -> None:
            self.peft_model.enable_input_require_grads()

        def gradient_checkpointing_enable(self, **kwargs: Any) -> None:
            self.peft_model.gradient_checkpointing_enable(**kwargs)

        def forward(
            self,
            input_ids: Any,
            attention_mask: Any,
            pooling_mask: Any | None = None,
            **_: Any,
        ) -> ReadoutOutput:
            classifier = self.peft_model.base_model.model
            outputs = classifier.model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                use_cache=False,
            )
            hidden = outputs.last_hidden_state
            pooled = self._pool(
                hidden,
                input_ids=input_ids,
                attention_mask=attention_mask,
                pooling_mask=pooling_mask,
            )
            return ReadoutOutput(logits=classifier.score(pooled))

        def _pool(
            self,
            hidden: Any,
            *,
            input_ids: Any,
            attention_mask: Any,
            pooling_mask: Any | None,
        ) -> Any:
            if self.readout_type in ("terminal", "fixed_terminal_anchor"):
                non_pad = (input_ids != self.config.pad_token_id).to(
                    hidden.device,
                    torch.int32,
                )
                indices = torch.arange(
                    input_ids.shape[-1],
                    device=hidden.device,
                    dtype=torch.int32,
                )
                last = (indices * non_pad).argmax(-1)
                return hidden[
                    torch.arange(hidden.shape[0], device=hidden.device),
                    last,
                ]
            if self.readout_type == "first_token":
                first = attention_mask.to(torch.int32).argmax(-1)
                return hidden[
                    torch.arange(hidden.shape[0], device=hidden.device),
                    first,
                ]
            if self.readout_type == "changed_hunk":
                if pooling_mask is None:
                    raise ValueError("changed_hunk readout requires pooling_mask")
                mask = pooling_mask.to(hidden.device) * attention_mask
                fallback = mask.sum(dim=1) == 0
                if fallback.any():
                    mask = mask.clone()
                    mask[fallback] = attention_mask[fallback]
            else:
                mask = attention_mask
            weights = mask.to(hidden.dtype).unsqueeze(-1)
            return (hidden * weights).sum(dim=1) / weights.sum(
                dim=1
            ).clamp_min(1.0)

    return ReadoutClassifier()

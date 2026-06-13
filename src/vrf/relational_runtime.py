from __future__ import annotations

from typing import Any

from vrf.relational_benchmark import changed_line_occurrences, insert_before_diff


def _encode(tokenizer: Any, text: str, *, add_special_tokens: bool) -> list[int]:
    return list(
        tokenizer.encode(text, add_special_tokens=add_special_tokens)
    )


def _offsets(
    tokenizer: Any, text: str, *, add_special_tokens: bool
) -> tuple[list[int], list[tuple[int, int]]]:
    if not getattr(tokenizer, "is_fast", False):
        raise ValueError(
            "Exact visibility accounting requires a fast tokenizer with "
            "offset mapping."
        )
    try:
        encoded = tokenizer(
            text,
            add_special_tokens=add_special_tokens,
            return_offsets_mapping=True,
            truncation=False,
        )
        return list(encoded["input_ids"]), [
            tuple(offset) for offset in encoded["offset_mapping"]
        ]
    except (TypeError, NotImplementedError, KeyError) as error:
        raise ValueError(
            "Fast tokenizer did not provide an exact offset_mapping."
        ) from error


def materialize_context_pressure(
    base_text: str,
    *,
    tokenizer: Any,
    target_ratio: float,
    add_special_tokens: bool,
) -> tuple[str, dict[str, Any]]:
    base_tokens = len(
        _encode(tokenizer, base_text, add_special_tokens=add_special_tokens)
    )
    target_padding_tokens = max(1, round(base_tokens * target_ratio))
    def candidate(lines: int) -> tuple[str, int]:
        padding = "Neutral context:\n" + ("// pad\n" * lines) + "\n"
        text = insert_before_diff(base_text, padding)
        token_count = len(
            _encode(tokenizer, text, add_special_tokens=add_special_tokens)
        )
        return text, token_count - base_tokens

    low, high = 1, 1
    best_text, best_tokens = candidate(1)
    while best_tokens < target_padding_tokens:
        high *= 2
        expanded_text, expanded_tokens = candidate(high)
        if abs(expanded_tokens - target_padding_tokens) < abs(
            best_tokens - target_padding_tokens
        ):
            best_text, best_tokens = expanded_text, expanded_tokens
        if expanded_tokens >= target_padding_tokens:
            break
        if high > target_padding_tokens * 8 + 1024:
            break
    while low <= high:
        lines = (low + high) // 2
        candidate_text, padding_tokens = candidate(lines)
        if abs(padding_tokens - target_padding_tokens) < abs(
            best_tokens - target_padding_tokens
        ):
            best_text = candidate_text
            best_tokens = padding_tokens
        if padding_tokens < target_padding_tokens:
            low = lines + 1
        elif padding_tokens > target_padding_tokens:
            high = lines - 1
        else:
            break
    marker_start = base_text.index("Unified diff from Side A to Side B:\n")
    inserted_length = len(best_text) - len(base_text)
    return best_text, {
        "target_budget_ratio": target_ratio,
        "target_padding_tokens": target_padding_tokens,
        "actual_padding_tokens": best_tokens,
        "achieved_budget_ratio": best_tokens / max(1, base_tokens),
        "transformation_char_spans": [
            {
                "char_start": marker_start,
                "char_end": marker_start + inserted_length,
            }
        ],
    }


def _visible_token_range(
    token_count: int, *, max_length: int, truncation_side: str
) -> tuple[int, int]:
    if token_count <= max_length:
        return 0, token_count
    if truncation_side == "left":
        return token_count - max_length, token_count
    return 0, max_length


def _occurrence_visibility(
    occurrences: list[dict[str, Any]],
    offsets: list[tuple[int, int]],
    *,
    visible_start: int,
    visible_end: int,
) -> dict[str, Any]:
    visible_indices = set(range(visible_start, visible_end))
    line_rows = []
    critical_token_indices: set[int] = set()
    visible_critical_tokens: set[int] = set()
    for occurrence in occurrences:
        token_indices = {
            index
            for index, (start, end) in enumerate(offsets)
            if end > occurrence["char_start"] and start < occurrence["char_end"]
        }
        critical_token_indices.update(token_indices)
        visible_tokens = token_indices & visible_indices
        visible_critical_tokens.update(visible_tokens)
        line_rows.append(
            {
                **occurrence,
                "token_start": min(token_indices) if token_indices else None,
                "token_end": max(token_indices) + 1 if token_indices else None,
                "tokens_total": len(token_indices),
                "tokens_visible": len(visible_tokens),
                "fully_visible": bool(token_indices)
                and token_indices.issubset(visible_indices),
            }
        )
    lines_visible = sum(row["fully_visible"] for row in line_rows)
    return {
        "critical_lines_total": len(line_rows),
        "critical_lines_visible": lines_visible,
        "critical_line_visibility_ratio": (
            lines_visible / len(line_rows) if line_rows else 1.0
        ),
        "critical_tokens_total": len(critical_token_indices),
        "critical_tokens_visible": len(visible_critical_tokens),
        "critical_token_visibility_ratio": (
            len(visible_critical_tokens) / len(critical_token_indices)
            if critical_token_indices
            else 1.0
        ),
        "first_critical_token": min(critical_token_indices)
        if critical_token_indices
        else None,
        "last_critical_token": max(critical_token_indices)
        if critical_token_indices
        else None,
        "critical_line_occurrences": line_rows,
    }


def runtime_accounting(
    text: str,
    *,
    tokenizer: Any,
    model_id: str,
    tokenizer_id: str,
    max_length: int,
    truncation_side: str,
    add_special_tokens: bool,
    transformation_char_spans: list[dict[str, int]] | None = None,
) -> dict[str, Any]:
    token_ids, offsets = _offsets(
        tokenizer, text, add_special_tokens=add_special_tokens
    )
    visible_start, visible_end = _visible_token_range(
        len(token_ids), max_length=max_length, truncation_side=truncation_side
    )
    visibility = _occurrence_visibility(
        changed_line_occurrences(text),
        offsets,
        visible_start=visible_start,
        visible_end=visible_end,
    )
    visible_indices = set(range(visible_start, visible_end))
    transformation_indices = {
        index
        for span in transformation_char_spans or []
        for index, (start, end) in enumerate(offsets)
        if end > span["char_start"] and start < span["char_end"]
    }
    return {
        "model_id": model_id,
        "tokenizer_id": tokenizer_id,
        "max_length": max_length,
        "truncation_side": truncation_side,
        "add_special_tokens": add_special_tokens,
        "offset_mapping_quality": "exact_fast_tokenizer",
        "token_count": len(token_ids),
        "visible_token_start": visible_start,
        "visible_token_end": visible_end,
        "truncated_tokens": max(0, len(token_ids) - max_length),
        "transformation_tokens_total": len(transformation_indices),
        "transformation_tokens_visible": len(
            transformation_indices & visible_indices
        ),
        **visibility,
        "critical_hunk_truncated": visibility["critical_line_visibility_ratio"]
        < 1.0,
    }


def materialize_runtime_rows(
    benchmark_rows: list[dict[str, Any]],
    *,
    tokenizer: Any,
    model_id: str,
    tokenizer_id: str,
    max_length: int,
    truncation_side: str = "right",
    add_special_tokens: bool = True,
) -> list[dict[str, Any]]:
    bases = {
        str(row["base_id"]): row
        for row in benchmark_rows
        if row["expected_relation"] == "identity"
    }
    base_accounting_cache: dict[str, dict[str, Any]] = {}
    output = []
    for row in benchmark_rows:
        text = str(row["text"])
        pressure = {}
        transform = row.get("runtime_transform") or {}
        transformation_char_spans = list(
            transform.get("transformation_char_spans") or []
        )
        if transform.get("operation") == "insert_token_budget_padding_before_diff":
            base = bases[str(row["base_id"])]
            text, pressure = materialize_context_pressure(
                str(base["text"]),
                tokenizer=tokenizer,
                target_ratio=float(transform["target_budget_ratio"]),
                add_special_tokens=add_special_tokens,
            )
        accounting = runtime_accounting(
            text,
            tokenizer=tokenizer,
            model_id=model_id,
            tokenizer_id=tokenizer_id,
            max_length=max_length,
            truncation_side=truncation_side,
            add_special_tokens=add_special_tokens,
            transformation_char_spans=pressure.get(
                "transformation_char_spans",
                transformation_char_spans,
            ),
        )
        if row["expected_relation"] == "identity":
            base_accounting = accounting
            base_accounting_cache[str(row["base_id"])] = accounting
        else:
            base_accounting = base_accounting_cache.get(str(row["base_id"]))
            if base_accounting is None:
                base_accounting = runtime_accounting(
                str(bases[str(row["base_id"])]["text"]),
                tokenizer=tokenizer,
                model_id=model_id,
                tokenizer_id=tokenizer_id,
                max_length=max_length,
                truncation_side=truncation_side,
                add_special_tokens=add_special_tokens,
            )
                base_accounting_cache[str(row["base_id"])] = base_accounting
        output.append(
            {
                **row,
                "text": text,
                "runtime_accounting": {
                    **accounting,
                    **pressure,
                    "base_critical_hunk_truncated": base_accounting[
                        "critical_hunk_truncated"
                    ],
                    "transformation_introduced_critical_truncation": (
                        accounting["critical_hunk_truncated"]
                        and not base_accounting["critical_hunk_truncated"]
                    ),
                },
            }
        )
    return output

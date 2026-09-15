"""Shared, fail-closed prediction indexing before any row aggregation."""
from __future__ import annotations

import math
from typing import Any


def unique_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result = {}
    for row in rows:
        row_id = row.get("id")
        if not isinstance(row_id, str) or not row_id.strip():
            raise ValueError("row id must be a nonempty string")
        if row_id in result:
            raise ValueError(f"duplicate row id: {row_id}")
        result[row_id] = row
    return result


def prediction_index(rows: list[dict[str, Any]], expected_ids=None, *, allow_extra=False):
    result = unique_rows(rows)
    models = set()
    for row in rows:
        model = row.get("model_id")
        if model is not None:
            if not isinstance(model, str) or not model.strip():
                raise ValueError("invalid model_id")
            models.add(model)
        for field in ("probability_a", "probability_b", "confidence"):
            value = row.get(field)
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))
                                      or not math.isfinite(value) or not 0 <= value <= 1):
                raise ValueError(f"invalid {field} for {row['id']}")
        a, b = row.get("probability_a"), row.get("probability_b")
        if a is not None and b is not None and not math.isclose(a + b, 1, abs_tol=1e-6):
            raise ValueError(f"probabilities do not sum to one: {row['id']}")
    if len(models) > 1 or (models and any(row.get("model_id") is None for row in rows)):
        raise ValueError("mixed or partially missing model identity")
    if expected_ids is not None:
        expected = set(expected_ids)
        missing, extra = expected - result.keys(), result.keys() - expected
        if missing or (extra and not allow_extra):
            raise ValueError(f"prediction coverage mismatch: missing={len(missing)}, extra={len(extra)}")
    return result


def validate_mapping(predictions, required_ids):
    rows = []
    for key, value in predictions.items():
        if "id" in value and value["id"] != key:
            raise ValueError("prediction key/id mismatch")
        rows.append({**value, "id": key})
    return prediction_index(rows, required_ids, allow_extra=True)

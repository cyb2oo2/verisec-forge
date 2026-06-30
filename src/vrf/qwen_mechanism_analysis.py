from __future__ import annotations

from collections import Counter
from statistics import mean
from typing import Any, Iterable


def changed_line_count(text: str) -> int:
    in_diff = False
    count = 0
    for line in text.splitlines():
        if line == "Unified diff from Side A to Side B:":
            in_diff = True
            continue
        if not in_diff or line.startswith(("---", "+++")):
            continue
        if line.startswith(("+", "-")):
            count += 1
    return count


def changed_line_bucket(count: int) -> str:
    if count <= 2:
        return "00-02"
    if count <= 5:
        return "03-05"
    if count <= 10:
        return "06-10"
    if count <= 25:
        return "11-25"
    return "26+"


def join_predictions(
    runtime_rows: Iterable[dict[str, Any]],
    predictions: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    prediction_by_id = {str(row["id"]): row for row in predictions}
    joined = []
    for row in runtime_rows:
        prediction = prediction_by_id.get(str(row["id"]))
        if prediction is None:
            raise ValueError(f"missing prediction for {row['id']}")
        joined.append({**row, **prediction})
    if len(joined) != len(prediction_by_id):
        raise ValueError("prediction IDs do not match runtime row IDs")
    return joined


def analyze_length(
    rows: list[dict[str, Any]],
    *,
    max_length: int,
) -> dict[str, Any]:
    by_id = {str(row["id"]): row for row in rows}
    canonical = {
        (str(row["dataset"]), str(row["pair_key"])): row
        for row in rows
        if row["audit_variant"] == "canonical"
    }
    training_prompt = {
        (str(row["dataset"]), str(row["pair_key"])): row
        for row in rows
        if row["audit_variant"] == "training_prompt"
    }
    variants = {}
    for variant in sorted({str(row["audit_variant"]) for row in rows}):
        variant_rows = [row for row in rows if row["audit_variant"] == variant]
        reference = (
            training_prompt
            if variant == "training_prompt_side_swap"
            else canonical
        )
        variants[variant] = _variant_metrics(variant_rows, reference)

    return {
        "max_length": max_length,
        "rows": len(rows),
        "pairs": len(canonical),
        "supports_abstention": all(
            bool(row.get("supports_abstention", False)) for row in rows
        ),
        "variants": variants,
        "datasets": {
            dataset: {
                variant: _variant_metrics(
                    [
                        row
                        for row in rows
                        if row["dataset"] == dataset
                        and row["audit_variant"] == variant
                    ],
                    (
                        training_prompt
                        if variant == "training_prompt_side_swap"
                        else canonical
                    ),
                )
                for variant in sorted(
                    {
                        str(row["audit_variant"])
                        for row in rows
                        if row["dataset"] == dataset
                    }
                )
            }
            for dataset in sorted({str(row["dataset"]) for row in rows})
        },
        "cross_length_key_count": len(by_id),
    }


def compare_lengths(
    short_rows: list[dict[str, Any]],
    long_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    short = {str(row["id"]): row for row in short_rows}
    long = {str(row["id"]): row for row in long_rows}
    if short.keys() != long.keys():
        raise ValueError("length settings must contain identical audit IDs")

    result = {}
    variants = sorted({str(row["audit_variant"]) for row in short_rows})
    for variant in variants:
        ids = [
            row_id
            for row_id, row in short.items()
            if row["audit_variant"] == variant
        ]
        changed = sum(
            short[row_id]["predicted_riskier_side"]
            != long[row_id]["predicted_riskier_side"]
            for row_id in ids
        )
        repaired = sum(
            short[row_id]["predicted_riskier_side"]
            != short[row_id]["gold_riskier_side"]
            and long[row_id]["predicted_riskier_side"]
            == long[row_id]["gold_riskier_side"]
            for row_id in ids
        )
        introduced = sum(
            short[row_id]["predicted_riskier_side"]
            == short[row_id]["gold_riskier_side"]
            and long[row_id]["predicted_riskier_side"]
            != long[row_id]["gold_riskier_side"]
            for row_id in ids
        )
        result[variant] = {
            "rows": len(ids),
            "decision_change_rate": _ratio(changed, len(ids)),
            "repaired_at_1024": repaired,
            "introduced_at_1024": introduced,
            "net_correct_delta": repaired - introduced,
        }
    return result


def _variant_metrics(
    rows: list[dict[str, Any]],
    canonical: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    if not rows:
        return {"rows": 0}
    clean_rows = [
        row
        for row in rows
        if _fully_visible(row)
        and _fully_visible(canonical[(str(row["dataset"]), str(row["pair_key"]))])
    ]
    metrics = _metrics(rows, canonical)
    metrics["clean_subset"] = _metrics(clean_rows, canonical)
    metrics["critical_hunk_truncated"] = sum(
        bool(row["runtime_accounting"]["critical_hunk_truncated"]) for row in rows
    )
    metrics["transformation_introduced_critical_truncation"] = sum(
        bool(
            row["runtime_accounting"][
                "transformation_introduced_critical_truncation"
            ]
        )
        for row in rows
    )
    metrics["mean_token_count"] = round(
        mean(row["runtime_accounting"]["token_count"] for row in rows), 3
    )
    counts = Counter(changed_line_bucket(changed_line_count(row["text"])) for row in rows)
    metrics["changed_line_buckets"] = dict(sorted(counts.items()))
    return metrics


def _metrics(
    rows: list[dict[str, Any]],
    canonical: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    if not rows:
        return {
            "rows": 0,
            "accuracy": None,
            "relation_accuracy": None,
            "a_to_b": 0,
            "b_to_a": 0,
        }
    correct = 0
    relation_success = 0
    a_to_b = 0
    b_to_a = 0
    for row in rows:
        base = canonical[(str(row["dataset"]), str(row["pair_key"]))]
        prediction = str(row["predicted_riskier_side"])
        base_prediction = str(base["predicted_riskier_side"])
        correct += prediction == str(row["gold_riskier_side"])
        if row["expected_relation"] == "equivariant_swap":
            relation_success += prediction != base_prediction
        else:
            relation_success += prediction == base_prediction
        a_to_b += base_prediction == "A" and prediction == "B"
        b_to_a += base_prediction == "B" and prediction == "A"
    return {
        "rows": len(rows),
        "accuracy": _ratio(correct, len(rows)),
        "relation_accuracy": _ratio(relation_success, len(rows)),
        "a_to_b": a_to_b,
        "b_to_a": b_to_a,
    }


def prediction_independence(
    predictions_a: dict[str, str],
    predictions_b: dict[str, str],
) -> dict[str, Any]:
    """2x2 chi-square test of independence + phi coefficient between two
    sets of A/B predictions keyed by the same identifier (e.g. pair_key).

    Used to distinguish "content-aware but mislabeled" failures (predictions
    correlate strongly, just with the wrong sign/side) from "content-blind"
    failures (predictions are statistically independent of each other,
    consistent with falling back to a positional/marginal prior).
    """
    import math

    keys = sorted(set(predictions_a) & set(predictions_b))
    n = len(keys)
    aa = sum(1 for k in keys if predictions_a[k] == "A" and predictions_b[k] == "A")
    ab = sum(1 for k in keys if predictions_a[k] == "A" and predictions_b[k] == "B")
    ba = sum(1 for k in keys if predictions_a[k] == "B" and predictions_b[k] == "A")
    bb = sum(1 for k in keys if predictions_a[k] == "B" and predictions_b[k] == "B")
    row_a, row_b = aa + ab, ba + bb
    col_a, col_b = aa + ba, ab + bb
    if n == 0 or row_a == 0 or row_b == 0 or col_a == 0 or col_b == 0:
        return {
            "n": n,
            "a_rate_first": _ratio(row_a, n),
            "a_rate_second": _ratio(col_a, n),
            "chi2": None,
            "phi": None,
            "p_value": None,
        }
    expected = [row_a * col_a / n, row_a * col_b / n, row_b * col_a / n, row_b * col_b / n]
    observed = [aa, ab, ba, bb]
    chi2 = sum((o - e) ** 2 / e for o, e in zip(observed, expected, strict=True))
    phi = (aa * bb - ab * ba) / math.sqrt(row_a * row_b * col_a * col_b)
    p_value = math.erfc(math.sqrt(chi2 / 2))
    return {
        "n": n,
        "a_rate_first": row_a / n,
        "a_rate_second": col_a / n,
        "chi2": chi2,
        "phi": phi,
        "p_value": p_value,
    }


def _fully_visible(row: dict[str, Any]) -> bool:
    return not bool(row["runtime_accounting"]["critical_hunk_truncated"])


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None

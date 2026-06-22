from __future__ import annotations

from collections import Counter
from typing import Any

from vrf.relational_evaluation import (
    evaluate_relational_predictions,
    join_predictions,
    normalize_label,
)


SIDE_SWAP_TEMPLATE = "canonical_renderer_swap_v2"
SUFFIX_TEMPLATE = "length_only_end_numbered_comments_v2"


def summarize_replication_model(
    benchmark_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
    *,
    model_key: str,
    model_type: str,
    model_id: str,
    tokenizer_id: str | None = None,
    supports_abstention: bool | None = None,
    bootstrap_iterations: int = 2000,
    bootstrap_seed: int = 42,
) -> dict[str, Any]:
    joined = join_predictions(benchmark_rows, prediction_rows)
    evaluation = evaluate_relational_predictions(
        joined,
        bootstrap_iterations=bootstrap_iterations,
        bootstrap_seed=bootstrap_seed,
    )
    headline_rows = [
        row
        for row in joined
        if str(row.get("sampling_suite") or "") == "representative"
    ]
    headline = _headline_relational_metrics(headline_rows)
    runtime = _runtime_summary(headline_rows)
    abstention = _abstention_summary(headline_rows)
    protocol = _protocol_summary(headline_rows)
    return {
        "model_key": model_key,
        "model_type": model_type,
        "model_id": model_id,
        "tokenizer_id": tokenizer_id,
        "supports_abstention": (
            abstention["supports_abstention"]
            if supports_abstention is None
            else supports_abstention
        ),
        "rows": len(joined),
        "headline_suite": "representative",
        "canonical_accuracy": headline["canonical_accuracy"],
        "side_swap_equivariance": headline["side_swap_equivariance"],
        "side_swap_independence_baseline": headline[
            "side_swap_independence_baseline"
        ],
        "side_swap_residual": headline["side_swap_residual"],
        "both_directions_correct": headline["both_directions_correct"],
        "suffix_consistency": headline["suffix_consistency"],
        "forced_only_suffix_consistency": headline[
            "forced_only_suffix_consistency"
        ],
        "forced_only_suffix_rows": headline["forced_only_suffix_rows"],
        "suffix_robust_accuracy": headline["suffix_robust_accuracy"],
        "invalid_output_rate": protocol["invalid_output_rate"],
        "insufficient_context_rate": abstention["insufficient_context_rate"],
        "runtime_visibility": runtime,
        "evaluation": evaluation,
    }


def build_replication_report(
    models: list[dict[str, Any]],
    *,
    scope: str = "minimal_broad_model_replication",
) -> dict[str, Any]:
    completed = [model for model in models if model.get("status", "ok") == "ok"]
    return {
        "status": (
            "ok"
            if len(completed) == len(models)
            else "partial_predictions"
            if completed
            else "pending_predictions"
        ),
        "scope": scope,
        "models": models,
        "completed_models": len(completed),
        "claim_boundary": (
            "This report is a model-family replication layer. It does not "
            "introduce new readout ablations, routers, calibration sweeps, "
            "or side-order architectures. Results answer whether relational "
            "failures appear across model mechanisms under the fixed "
            "VeriPatch-RR protocol."
        ),
    }


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# Cross-Model Replication",
        "",
        "PR #12 asks whether VeriPatch-RR failures generalize across model mechanisms.",
        "It intentionally avoids new Qwen readout variants, routers, calibration, or side-order architectures.",
        "",
        "| model | type | canonical | swap residual | both correct | strict suffix | forced-only suffix | invalid | insufficient context | interpretation |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for model in report["models"]:
        if model.get("status") == "pending":
            lines.append(
                f"| `{model['model_key']}` | {model['model_type']} | n/a | n/a | n/a | n/a | n/a | n/a | n/a | {model['interpretation']} |"
            )
            continue
        lines.append(
            f"| `{model['model_key']}` | {model['model_type']} | "
            f"{_pct(model['canonical_accuracy'])} | "
            f"{_signed(model['side_swap_residual'])} | "
            f"{_pct(model['both_directions_correct'])} | "
            f"{_pct(model['suffix_consistency'])} | "
            f"{_pct(model['forced_only_suffix_consistency'])} "
            f"({model['forced_only_suffix_rows']}) | "
            f"{_pct(model['invalid_output_rate'])} | "
            f"{_pct(model['insufficient_context_rate'])} | "
            f"{model.get('interpretation', '')} |"
        )
    lines.extend(
        [
            "",
            "## Current Interpretation",
            "",
            "- `partial_predictions` means at least one required model slot has been evaluated, while at least one remains pending.",
            "- Generative judge rows use strict output parsing. Invalid outputs are not repaired or manually relabeled.",
            "- Strict suffix consistency counts `INVALID` and `INSUFFICIENT_CONTEXT` as failures; forced-only suffix consistency is a secondary diagnostic over rows where both base and suffix outputs are forced A/B labels.",
            "- If invalid output rate exceeds 20%, the row should be interpreted as a protocol-following limitation as well as a relational result.",
            "- The current completed generative slot uses `Qwen/Qwen2.5-0.5B-Instruct`; it broadens the mechanism beyond classification heads, but it is not a non-Qwen-family replication.",
            "- A low side-swap residual together with low both-directions-correct indicates that the judge is not reliably flipping its decision under A/B side swaps.",
            "",
            "## Required Model Slots",
            "",
            "- **Non-Qwen decoder classifier:** tests whether terminal/readout endpoint sensitivity is Qwen-specific or broader among decoder classifiers.",
            "- **Generative instruction judge:** tests whether side-order inconsistency also appears without a classification head.",
            "",
            "## Claim Boundary",
            "",
            report["claim_boundary"],
            "",
        ]
    )
    return "\n".join(lines)


def pending_model(
    *,
    model_key: str,
    model_type: str,
    interpretation: str,
) -> dict[str, Any]:
    return {
        "status": "pending",
        "model_key": model_key,
        "model_type": model_type,
        "interpretation": interpretation,
    }


def _headline_relational_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {str(row["id"]): row for row in rows}
    base_rows = [
        row for row in rows if str(row["expected_relation"]) == "identity"
    ]
    side_swap_rows = [
        row
        for row in rows
        if str(row["transformation_template"]) == SIDE_SWAP_TEMPLATE
    ]
    suffix_rows = [
        row
        for row in rows
        if str(row["transformation_template"]) == SUFFIX_TEMPLATE
    ]
    base_predictions = {
        str(row["id"]): normalize_label(row["predicted_riskier_side"])
        for row in base_rows
    }
    canonical_accuracy = _mean(
        normalize_label(row["predicted_riskier_side"])
        == normalize_label(row["gold_riskier_side"])
        for row in base_rows
    )
    side_swap_success = []
    side_swap_both_correct = []
    base_b = []
    swap_b = []
    for row in side_swap_rows:
        base = by_id.get(str(row["base_id"]))
        if base is None:
            continue
        base_prediction = normalize_label(base["predicted_riskier_side"])
        swap_prediction = normalize_label(row["predicted_riskier_side"])
        side_swap_success.append(_is_forced(base_prediction) and _is_forced(swap_prediction) and base_prediction != swap_prediction)
        base_b.append(base_prediction == "B")
        swap_b.append(swap_prediction == "B")
        side_swap_both_correct.append(
            base_prediction == normalize_label(base["gold_riskier_side"])
            and swap_prediction == normalize_label(row["gold_riskier_side"])
        )
    base_b_rate = _mean(base_b)
    swap_b_rate = _mean(swap_b)
    independence = (
        None
        if base_b_rate is None or swap_b_rate is None
        else base_b_rate * (1.0 - swap_b_rate)
        + (1.0 - base_b_rate) * swap_b_rate
    )
    side_swap = _mean(side_swap_success)
    suffix_success = []
    forced_suffix_success = []
    suffix_robust = []
    for row in suffix_rows:
        base_prediction = base_predictions.get(str(row["base_id"]))
        transformed = normalize_label(row["predicted_riskier_side"])
        success = (
            _is_forced(base_prediction)
            and _is_forced(transformed)
            and base_prediction == transformed
        )
        suffix_success.append(success)
        if _is_forced(base_prediction) and _is_forced(transformed):
            forced_suffix_success.append(base_prediction == transformed)
        suffix_robust.append(
            success
            and base_prediction
            == normalize_label(by_id[str(row["base_id"])]["gold_riskier_side"])
            and transformed == normalize_label(row["gold_riskier_side"])
        )
    return {
        "canonical_accuracy": canonical_accuracy,
        "side_swap_equivariance": side_swap,
        "side_swap_independence_baseline": independence,
        "side_swap_residual": (
            None if side_swap is None or independence is None else side_swap - independence
        ),
        "both_directions_correct": _mean(side_swap_both_correct),
        "suffix_consistency": _mean(suffix_success),
        "forced_only_suffix_consistency": _mean(forced_suffix_success),
        "forced_only_suffix_rows": len(forced_suffix_success),
        "suffix_robust_accuracy": _mean(suffix_robust),
    }


def _runtime_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    accountings = [row.get("runtime_accounting") or {} for row in rows]
    return {
        "rows": len(rows),
        "critical_hunk_truncated_rate": _mean(
            bool(row.get("critical_hunk_truncated")) for row in accountings
        ),
        "transformation_introduced_critical_truncation_rate": _mean(
            bool(row.get("transformation_introduced_critical_truncation"))
            for row in accountings
        ),
        "offset_mapping_quality": sorted(
            {str(row.get("offset_mapping_quality")) for row in accountings}
        ),
    }


def _abstention_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [normalize_label(row["predicted_riskier_side"]) for row in rows]
    return {
        "supports_abstention": any(
            bool(row.get("supports_abstention")) for row in rows
        ),
        "insufficient_context_rate": _mean(
            label == "INSUFFICIENT_CONTEXT" for label in labels
        ),
        "prediction_counts": dict(Counter(labels)),
    }


def _protocol_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [normalize_label(row["predicted_riskier_side"]) for row in rows]
    return {
        "invalid_output_rate": _mean(label == "INVALID" for label in labels),
    }


def _is_forced(label: str | None) -> bool:
    return label in {"A", "B"}


def _mean(values) -> float | None:
    values = list(values)
    return sum(bool(value) for value in values) / len(values) if values else None


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.2f}%"


def _signed(value: float | None) -> str:
    return "n/a" if value is None else f"{value:+.4f}"

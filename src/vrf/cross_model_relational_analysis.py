from __future__ import annotations

from typing import Any

from vrf.qwen_mechanism_analysis import analyze_length


REQUIRED_VARIANTS = (
    "canonical",
    "side_swap",
    "canonical_no_metadata",
    "padding_pre_diff",
    "padding_post_diff",
    "padding_post_diff_terminal_phrase",
)


def summarize_model(
    rows: list[dict[str, Any]],
    *,
    model_metadata: dict[str, Any],
    max_length: int,
) -> dict[str, Any]:
    report = analyze_length(rows, max_length=max_length)
    variants = report["variants"]
    grouped: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    for row in rows:
        key = (str(row["dataset"]), str(row["pair_key"]))
        grouped.setdefault(key, {})[str(row["audit_variant"])] = row

    robust = 0
    clean_robust = 0
    complete = 0
    for group in grouped.values():
        if not all(variant in group for variant in REQUIRED_VARIANTS):
            continue
        complete += 1
        canonical = group["canonical"]
        canonical_prediction = str(canonical["predicted_riskier_side"])
        correct = canonical_prediction == str(canonical["gold_riskier_side"])
        relations = []
        for variant in REQUIRED_VARIANTS[1:]:
            transformed = group[variant]
            if transformed["expected_relation"] == "equivariant_swap":
                relations.append(
                    transformed["predicted_riskier_side"]
                    != canonical_prediction
                )
            else:
                relations.append(
                    transformed["predicted_riskier_side"]
                    == canonical_prediction
                )
        success = correct and all(relations)
        robust += success
        all_visible = all(
            not row["runtime_accounting"]["critical_hunk_truncated"]
            for row in group.values()
        )
        clean_robust += success and all_visible

    post = variants["padding_post_diff"]
    terminal = variants["padding_post_diff_terminal_phrase"]
    return {
        "metadata": model_metadata,
        "rows": len(rows),
        "pairs": complete,
        "canonical_accuracy": variants["canonical"]["accuracy"],
        "side_swap_equivariance": variants["side_swap"]["relation_accuracy"],
        "metadata_removed_relation": variants["canonical_no_metadata"][
            "relation_accuracy"
        ],
        "pre_diff_relation": variants["padding_pre_diff"][
            "relation_accuracy"
        ],
        "post_diff_relation": post["relation_accuracy"],
        "terminal_phrase_relation": terminal["relation_accuracy"],
        "post_diff_a_to_b": post["a_to_b"],
        "post_diff_b_to_a": post["b_to_a"],
        "clean_post_diff_relation": post["clean_subset"]["relation_accuracy"],
        "robust_accuracy": robust / complete if complete else None,
        "clean_robust_accuracy": (
            clean_robust / complete if complete else None
        ),
        "canonical_critical_hunk_truncated": variants["canonical"][
            "critical_hunk_truncated"
        ],
    }

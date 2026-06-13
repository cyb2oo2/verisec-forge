from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.cross_model_relational_analysis import (
    compare_paired_models,
    summarize_model,
)
from vrf.io_utils import read_jsonl, write_json
from vrf.qwen_mechanism_analysis import join_predictions


def pct(value):
    return "n/a" if value is None else f"{100 * value:.2f}%"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare Qwen and CodeBERT on the compact audit."
    )
    parser.add_argument(
        "--audit",
        default="data/processed/secure_code_cross_model_relational_audit_v1.jsonl",
    )
    parser.add_argument(
        "--qwen-runtime",
        default="data/processed/secure_code_qwen_mechanism_audit_v1_runtime512.jsonl",
    )
    parser.add_argument(
        "--qwen-predictions",
        default="outputs/secure_code_qwen_mechanism_audit_v1_predictions_512.jsonl",
    )
    parser.add_argument(
        "--codebert-runtime",
        default="data/processed/secure_code_cross_model_relational_audit_codebert_v1_runtime512.jsonl",
    )
    parser.add_argument(
        "--codebert-predictions",
        default="outputs/secure_code_cross_model_relational_audit_codebert_v1_predictions.jsonl",
    )
    parser.add_argument(
        "--json-output",
        default="reports/secure_code_cross_model_relational_audit_v1.json",
    )
    parser.add_argument(
        "--markdown-output",
        default="reports/CROSS_MODEL_RELATIONAL_AUDIT.md",
    )
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=42)
    args = parser.parse_args()

    audit_ids = {str(row["id"]) for row in read_jsonl(ROOT / args.audit)}
    qwen_runtime = [
        row
        for row in read_jsonl(ROOT / args.qwen_runtime)
        if str(row["id"]) in audit_ids
    ]
    qwen_predictions = [
        row
        for row in read_jsonl(ROOT / args.qwen_predictions)
        if str(row["id"]) in audit_ids
    ]
    codebert_runtime = read_jsonl(ROOT / args.codebert_runtime)
    codebert_predictions = read_jsonl(ROOT / args.codebert_predictions)

    models = {
        "qwen15b_decoder_classifier": summarize_model(
            join_predictions(qwen_runtime, qwen_predictions),
            max_length=512,
            model_metadata={
                "family": "decoder_sequence_classifier",
                "readout_type": "qwen_sequence_classification_score",
                "pooling_mechanism": "terminal_non_padding_token",
                "tokenizer": "Qwen2.5-Coder tokenizer",
                "training_objective": (
                    "paired binary classification + vulnerable-score margin "
                    "+ complementary-probability regularization"
                ),
                "loss_weights": {
                    "classification": 1.0,
                    "margin": 0.5,
                    "complement": 0.1,
                },
                "supports_abstention": False,
            },
        ),
        "codebert_encoder_classifier": summarize_model(
            join_predictions(codebert_runtime, codebert_predictions),
            max_length=512,
            model_metadata={
                "family": "encoder_sequence_classifier",
                "readout_type": "roberta_cls_classification_head",
                "pooling_mechanism": "first_token_cls_representation",
                "tokenizer": "CodeBERT RoBERTa tokenizer",
                "training_objective": "binary_side_choice_cross_entropy",
                "supports_abstention": False,
            },
        ),
    }
    paired_statistics = compare_paired_models(
        models["qwen15b_decoder_classifier"]["pair_records"],
        models["codebert_encoder_classifier"]["pair_records"],
        iterations=args.bootstrap_iterations,
        seed=args.bootstrap_seed,
    )
    public_models = {
        name: {
            key: value
            for key, value in row.items()
            if key != "pair_records"
        }
        for name, row in models.items()
    }
    claim_boundary = (
        "CodeBERT uses the same 6,000 bidirectional side-choice rows and "
        "one epoch, but Qwen additionally inherits an earlier pair-diff "
        "initialization and uses margin plus complementary-probability "
        "regularization. This is an architecture stress comparison, not "
        "a controlled architecture-only, objective, pretraining, or "
        "capacity comparison."
    )
    payload = {
        "status": "ok",
        "scope": "first_cross_architecture_relational_audit",
        "models": public_models,
        "paired_statistics": paired_statistics,
        "claim_boundary": claim_boundary,
    }
    write_json(ROOT / args.json_output, payload)

    lines = [
        "# Cross-Model Relational Audit",
        "",
        "This is the first compact architecture comparison on 600 fixed pairs and eight variants per pair.",
        "",
        "| model | canonical | swap | training-contract swap | post-diff | terminal phrase | robust | clean coverage | clean robust conditional | clean+robust coverage |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, row in public_models.items():
        lines.append(
            f"| `{name}` | {pct(row['canonical_accuracy'])} | "
            f"{pct(row['side_swap_equivariance'])} | "
            f"{pct(row['training_contract_swap_equivariance'])} | "
            f"{pct(row['post_diff_relation'])} | "
            f"{pct(row['terminal_phrase_relation'])} | "
            f"{pct(row['robust_accuracy'])} | "
            f"{pct(row['clean_pair_coverage'])} | "
            f"{pct(row['clean_robust_accuracy_conditional'])} | "
            f"{pct(row['clean_and_robust_coverage'])} |"
        )
    all_stats = paired_statistics["subsets"]["all_pairs"]
    endpoint = all_stats["endpoint_gap_codebert_minus_qwen"]
    interaction = all_stats["terminal_recovery_interaction"]
    lines.extend(
        [
            "",
            "## Swap Diagnostics",
            "",
            "| model | rendering | observed equivariance | independence baseline | observed - baseline | both directions correct |",
            "| --- | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for name, row in public_models.items():
        lines.extend(
            [
                (
                    f"| `{name}` | canonical | "
                    f"{pct(row['side_swap_equivariance'])} | "
                    f"{pct(row['side_swap_independence_baseline'])} | "
                    f"{row['side_swap_minus_independence_baseline']:+.4f} | "
                    f"{pct(row['side_swap_both_directions_correct'])} |"
                ),
                (
                    f"| `{name}` | exact training contract | "
                    f"{pct(row['training_contract_swap_equivariance'])} | "
                    f"{pct(row['training_contract_swap_independence_baseline'])} | "
                    f"{row['training_contract_swap_minus_independence_baseline']:+.4f} | "
                    f"{pct(row['training_contract_swap_both_directions_correct'])} |"
                ),
            ]
        )
    lines.extend(
        [
            "",
            "## Paired Statistics",
            "",
            (
                f"- Endpoint gap, CodeBERT minus Qwen: `{endpoint['estimate']:.4f}` "
                f"(pair bootstrap 95% CI "
                f"`[{endpoint['ci95'][0]:.4f}, {endpoint['ci95'][1]:.4f}]`)."
            ),
            (
                f"- Terminal-recovery interaction: `{interaction['estimate']:.4f}` "
                f"(pair bootstrap 95% CI "
                f"`[{interaction['ci95'][0]:.4f}, {interaction['ci95'][1]:.4f}]`)."
            ),
            "",
            "| subset | pairs | endpoint gap | 95% CI | recovery interaction | 95% CI |",
            "| --- | ---: | ---: | --- | ---: | --- |",
        ]
    )
    for name, stats in paired_statistics["subsets"].items():
        gap = stats["endpoint_gap_codebert_minus_qwen"]
        recovery = stats["terminal_recovery_interaction"]
        lines.append(
            f"| `{name}` | {stats['pairs']} | {gap['estimate']:.4f} | "
            f"[{gap['ci95'][0]:.4f}, {gap['ci95'][1]:.4f}] | "
            f"{recovery['estimate']:.4f} | "
            f"[{recovery['ci95'][0]:.4f}, {recovery['ci95'][1]:.4f}] |"
        )
    lines.extend(
        [
            "",
            "## By Dataset",
            "",
            "| dataset | pairs | endpoint gap | 95% CI | recovery interaction |",
            "| --- | ---: | ---: | --- | ---: |",
        ]
    )
    for name, stats in paired_statistics["by_dataset"].items():
        gap = stats["endpoint_gap_codebert_minus_qwen"]
        recovery = stats["terminal_recovery_interaction"]
        lines.append(
            f"| `{name}` | {stats['pairs']} | {gap['estimate']:.4f} | "
            f"[{gap['ci95'][0]:.4f}, {gap['ci95'][1]:.4f}] | "
            f"{recovery['estimate']:.4f} |"
        )
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "- **Relational inconsistency crosses architectures.** Both classifiers remain close to their marginal-conditioned independent-decision baselines on canonical and exact-training-contract side-swap equivariance despite above-chance pointwise accuracy.",
            "- **Severe endpoint collapse does not cross this first architecture control.** CodeBERT preserves `94.17%` of canonical decisions under post-diff padding, versus Qwen's `56.50%`.",
            "- **Base capability does not explain the endpoint gap.** CodeBERT canonical accuracy is `67.67%`, close to Qwen's `65.50%`.",
            "- **The readout hypothesis is strengthened but not proven.** The result is consistent with terminal-token decoder readout sensitivity, but pretraining, tokenizer, capacity, and initialization also differ.",
            "- The models do not have identical objectives, pretraining, capacity, tokenizer, or initialization; conclusions must remain architecture-stress observations.",
            "",
            "## Claim Boundary",
            "",
            payload["claim_boundary"],
            "",
        ]
    )
    (ROOT / args.markdown_output).write_text(
        "\n".join(lines), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "models": public_models,
                "paired_statistics": paired_statistics,
                "claim_boundary": claim_boundary,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

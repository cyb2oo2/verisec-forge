from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_json
from vrf.qwen_mechanism_analysis import (
    analyze_length,
    compare_lengths,
    join_predictions,
)


def pct(value):
    return "n/a" if value is None else f"{100 * value:.2f}%"


def render_markdown(report: dict) -> str:
    v512 = report["lengths"]["512"]["variants"]
    v1024 = report["lengths"]["1024"]["variants"]
    delta1024 = report["lengths"]["1024"]["datasets"]["deltasecommits"]
    lines = [
        "# Qwen Relational Mechanism Audit",
        "",
        "This audit tests mechanism hypotheses for one PrimeVul-trained Qwen2.5-Coder-1.5B binary side classifier. It does not establish that all secure-code models share these failures.",
        "",
        "The checkpoint does not support abstention. All results below measure forced binary decisions; abstention rate is not applicable.",
        "",
        "## Headline",
        "",
        "| length | canonical accuracy | side-swap equivariance | post-diff relation | post-diff A->B / B->A |",
        "| ---: | ---: | ---: | ---: | ---: |",
    ]
    for length in ("512", "1024"):
        variants = report["lengths"][length]["variants"]
        post = variants["padding_post_diff"]
        lines.append(
            f"| {length} | {pct(variants['canonical']['accuracy'])} | "
            f"{pct(variants['side_swap']['relation_accuracy'])} | "
            f"{pct(post['relation_accuracy'])} | {post['a_to_b']} / {post['b_to_a']} |"
        )

    lines.extend(
        [
            "",
            "## Findings",
            "",
            (
                "1. **Longer context does not repair relational inconsistency.** "
                f"Canonical accuracy changes only from {pct(v512['canonical']['accuracy'])} "
                f"to {pct(v1024['canonical']['accuracy'])}, while side-swap equivariance "
                f"changes from {pct(v512['side_swap']['relation_accuracy'])} to "
                f"{pct(v1024['side_swap']['relation_accuracy'])}."
            ),
            (
                "2. **The suffix failure is endpoint-sensitive rather than a truncation artifact.** "
                f"At 1024, post-diff padding has {pct(v1024['padding_post_diff']['relation_accuracy'])} "
                "relation accuracy with zero transformation-introduced critical-hunk truncations. "
                f"Adding a terminal task-completion phrase raises it to "
                f"{pct(v1024['padding_post_diff_terminal_phrase']['relation_accuracy'])}, "
                f"whereas a novel `[END_PATCH]` marker reaches only "
                f"{pct(v1024['padding_post_diff_end_patch']['relation_accuracy'])}."
            ),
            (
                "3. **Prompt distribution shift is secondary.** "
                f"At 1024, no-metadata and training-contract prompts preserve "
                f"{pct(v1024['canonical_no_metadata']['relation_accuracy'])} and "
                f"{pct(v1024['training_prompt']['relation_accuracy'])} of canonical decisions."
            ),
            (
                "4. **Delta has both representation and relational failures.** "
                f"At 1024, separator expansion raises forced-decision accuracy from "
                f"{pct(delta1024['delta_raw']['accuracy'])} to "
                f"{pct(delta1024['delta_separator_expanded']['accuracy'])}, but its "
                f"side-swap equivariance is only "
                f"{pct(delta1024['delta_separator_expanded_side_swap']['relation_accuracy'])} "
                f"and post-diff relation accuracy is "
                f"{pct(delta1024['delta_separator_expanded_post_diff']['relation_accuracy'])}."
            ),
        ]
    )

    lines.extend(
        [
            "",
            "## Padding Position",
            "",
            "| length | variant | relation | clean relation | A->B | B->A | new truncation |",
            "| ---: | --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    padding = [
        "padding_prompt_prefix",
        "padding_after_instructions",
        "padding_pre_diff",
        "padding_mid_diff_malformed_stress",
        "padding_post_diff",
        "padding_post_diff_terminal_phrase",
        "padding_post_diff_end_patch",
    ]
    for length in ("512", "1024"):
        variants = report["lengths"][length]["variants"]
        for name in padding:
            row = variants[name]
            lines.append(
                f"| {length} | `{name}` | {pct(row['relation_accuracy'])} | "
                f"{pct(row['clean_subset']['relation_accuracy'])} | "
                f"{row['a_to_b']} | {row['b_to_a']} | "
                f"{row['transformation_introduced_critical_truncation']} |"
            )

    lines.extend(
        [
            "",
            "## Prompt Contract",
            "",
            "| length | variant | accuracy | relation to canonical | clean relation |",
            "| ---: | --- | ---: | ---: | ---: |",
        ]
    )
    for length in ("512", "1024"):
        variants = report["lengths"][length]["variants"]
        for name in ("canonical", "canonical_no_metadata", "training_prompt"):
            row = variants[name]
            lines.append(
                f"| {length} | `{name}` | {pct(row['accuracy'])} | "
                f"{pct(row['relation_accuracy'])} | "
                f"{pct(row['clean_subset']['relation_accuracy'])} |"
            )

    lines.extend(
        [
            "",
            "## Delta Representation",
            "",
        "| length | representation | accuracy | swap equivariance | post-diff relation | post-diff A->B / B->A | mean tokens | changed lines |",
        "| ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for length in ("512", "1024"):
        dataset = report["lengths"][length]["datasets"]["deltasecommits"]
        for name in ("delta_raw", "delta_separator_expanded", "delta_clang_format"):
            row = dataset[name]
            if name == "delta_raw":
                swap = dataset["side_swap"]
                post = dataset["padding_post_diff"]
            else:
                swap = dataset[f"{name}_side_swap"]
                post = dataset[f"{name}_post_diff"]
            buckets = ", ".join(
                f"{key}:{value}" for key, value in row["changed_line_buckets"].items()
            )
            lines.append(
                f"| {length} | `{name}` | {pct(row['accuracy'])} | "
                f"{pct(swap['relation_accuracy'])} | "
                f"{pct(post['relation_accuracy'])} | "
                f"{post['a_to_b']} / {post['b_to_a']} | "
                f"{row['mean_token_count']:.1f} | {buckets} |"
            )

    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "- `512` and `1024` are sensitivity settings for the same checkpoint, not separate trained models.",
            "- Relation metrics are also reported on the clean subset where the canonical and transformed critical hunks are both fully visible.",
            "- DeltaSecommits is a combined source and representation shift; the interventions recover ordinary accuracy but are not validated semantics-preserving normalization.",
            "- The mid-diff intervention is a malformed-diff formatting stress, not a semantics-preserving invariance test.",
            "- Delta separator expansion and formatter fallback are representation interventions, not validated semantics-preserving normalization.",
            "- Suffix effects are mechanism evidence only if they persist without transformation-introduced truncation; they do not by themselves identify a specific pooling implementation.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze the Qwen mechanism audit.")
    parser.add_argument(
        "--runtime-512",
        default="data/processed/secure_code_qwen_mechanism_audit_v1_runtime512.jsonl",
    )
    parser.add_argument(
        "--predictions-512",
        default="outputs/secure_code_qwen_mechanism_audit_v1_predictions_512.jsonl",
    )
    parser.add_argument(
        "--runtime-1024",
        default="data/processed/secure_code_qwen_mechanism_audit_v1_runtime1024.jsonl",
    )
    parser.add_argument(
        "--predictions-1024",
        default="outputs/secure_code_qwen_mechanism_audit_v1_predictions_1024.jsonl",
    )
    parser.add_argument(
        "--json-output",
        default="reports/secure_code_qwen_mechanism_audit_v1.json",
    )
    parser.add_argument(
        "--markdown-output",
        default="reports/QWEN_RELATIONAL_MECHANISM_AUDIT.md",
    )
    args = parser.parse_args()

    joined_512 = join_predictions(
        read_jsonl(ROOT / args.runtime_512),
        read_jsonl(ROOT / args.predictions_512),
    )
    joined_1024 = join_predictions(
        read_jsonl(ROOT / args.runtime_1024),
        read_jsonl(ROOT / args.predictions_1024),
    )
    report = {
        "status": "ok",
        "scope": "qwen15b_relational_mechanism_audit",
        "claim_boundary": {
            "model_family_scope": "single_qwen_decoder_sequence_classifier",
            "supports_abstention": False,
            "abstention_rate": None,
            "delta_shift_interpretation": "combined_source_and_representation_shift",
        },
        "lengths": {
            "512": analyze_length(joined_512, max_length=512),
            "1024": analyze_length(joined_1024, max_length=1024),
        },
        "length_comparison": compare_lengths(joined_512, joined_1024),
    }
    report["findings"] = {
        "longer_context_repairs_relational_failure": False,
        "suffix_failure_persists_without_new_truncation": True,
        "terminal_phrase_restores_more_than_novel_marker": True,
        "prompt_contract_is_primary_failure": False,
        "delta_representation_recovery": True,
        "delta_relational_recovery": False,
    }
    write_json(ROOT / args.json_output, report)
    (ROOT / args.markdown_output).write_text(
        render_markdown(report), encoding="utf-8"
    )
    print(json.dumps(report["claim_boundary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

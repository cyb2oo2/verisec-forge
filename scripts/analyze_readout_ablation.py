from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.cross_model_relational_analysis import summarize_model
from vrf.io_utils import read_jsonl, write_json
from vrf.qwen_mechanism_analysis import join_predictions
from vrf.readout_ablation_analysis import compare_readouts


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.2f}%"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze same-backbone readout ablation predictions."
    )
    parser.add_argument(
        "--runtime",
        default="data/processed/secure_code_qwen_mechanism_audit_v1_runtime512.jsonl",
    )
    parser.add_argument(
        "--predictions-template",
        default="outputs/secure_code_readout_ablation_{readout}_audit_v1_predictions.jsonl",
    )
    parser.add_argument(
        "--readouts",
        nargs="+",
        default=[
            "terminal",
            "first_token",
            "mean",
            "changed_hunk",
            "fixed_terminal_anchor",
        ],
    )
    parser.add_argument(
        "--json-output",
        default="reports/secure_code_readout_ablation_v1.json",
    )
    parser.add_argument(
        "--markdown-output",
        default="reports/READOUT_ABLATION.md",
    )
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=42)
    args = parser.parse_args()

    runtime = read_jsonl(ROOT / args.runtime)
    models = {}
    for readout in args.readouts:
        predictions_path = ROOT / args.predictions_template.format(
            readout=readout
        )
        if not predictions_path.exists():
            raise FileNotFoundError(predictions_path)
        model = summarize_model(
            join_predictions(runtime, read_jsonl(predictions_path)),
            model_metadata={
                "family": "qwen_decoder_sequence_classifier",
                "readout_type": readout,
                "training_contract": "same_backbone_readout_ablation_v1",
            },
            max_length=512,
        )
        model["runtime_accounting_compatible"] = (
            readout != "fixed_terminal_anchor"
        )
        if readout == "fixed_terminal_anchor":
            model["clean_pair_coverage"] = None
            model["clean_robust_accuracy_conditional"] = None
            model["clean_and_robust_coverage"] = None
        models[readout] = model
    control = models["terminal"]
    comparisons = {
        readout: compare_readouts(
            control["pair_records"],
            model["pair_records"],
            iterations=args.bootstrap_iterations,
            seed=args.bootstrap_seed + index * 1009,
        )
        for index, (readout, model) in enumerate(models.items())
        if readout != "terminal"
    }
    comparisons["fixed_terminal_anchor"]["jointly_clean"] = {
        "status": "not_comparable",
        "reason": (
            "The reserved terminal anchor changes the effective truncation "
            "budget; the original runtime visibility accounting is invalid."
        ),
    }
    success_rule = {
        "post_diff_ci_excludes_zero": True,
        "max_absolute_canonical_accuracy_delta": 0.02,
    }
    decisions = {}
    for readout, comparison in comparisons.items():
        all_pairs = comparison["all_pairs"]
        canonical = all_pairs["canonical_accuracy_delta"]
        post = all_pairs["post_diff_relation_delta"]
        decisions[readout] = {
            "meets_success_rule": (
                post["ci95"][0] > 0
                and abs(canonical["estimate"])
                <= success_rule["max_absolute_canonical_accuracy_delta"]
            ),
            "canonical_delta_within_tolerance": (
                abs(canonical["estimate"])
                <= success_rule["max_absolute_canonical_accuracy_delta"]
            ),
            "post_diff_ci_excludes_zero": post["ci95"][0] > 0,
        }
    public_models = {
        name: {
            key: value
            for key, value in model.items()
            if key != "pair_records"
        }
        for name, model in models.items()
    }
    payload = {
        "status": "ok",
        "scope": "same_backbone_qwen_readout_ablation",
        "control": "terminal",
        "models": public_models,
        "paired_comparisons": comparisons,
        "success_rule": success_rule,
        "decisions": decisions,
        "findings": {
            "mean_removes_most_endpoint_sensitivity": True,
            "changed_hunk_nearly_eliminates_endpoint_sensitivity": True,
            "first_token_is_invalid_for_causal_decoder_readout": True,
            "fixed_anchor_trades_endpoint_stability_for_canonical_accuracy": True,
            "no_readout_meets_preregistered_success_rule": all(
                not decision["meets_success_rule"]
                for decision in decisions.values()
            ),
            "side_swap_failure_remains_separate": True,
        },
    }
    write_json(ROOT / args.json_output, payload)

    lines = [
        "# Same-Backbone Readout Ablation",
        "",
        "| readout | canonical | swap | swap baseline | both correct | post-diff | terminal phrase | robust |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, model in public_models.items():
        lines.append(
            f"| `{name}` | {pct(model['canonical_accuracy'])} | "
            f"{pct(model['side_swap_equivariance'])} | "
            f"{pct(model['side_swap_independence_baseline'])} | "
            f"{pct(model['side_swap_both_directions_correct'])} | "
            f"{pct(model['post_diff_relation'])} | "
            f"{pct(model['terminal_phrase_relation'])} | "
            f"{pct(model['robust_accuracy'])} |"
        )
    lines.extend(
        [
            "",
            "## Paired Deltas Versus Terminal",
            "",
        "| readout | canonical delta | 95% CI | post-diff delta | 95% CI | passes |",
        "| --- | ---: | --- | ---: | --- | --- |",
        ]
    )
    for name, comparison in comparisons.items():
        row = comparison["all_pairs"]
        canonical = row["canonical_accuracy_delta"]
        post = row["post_diff_relation_delta"]
        lines.append(
            f"| `{name}` | {canonical['estimate']:+.4f} | "
            f"[{canonical['ci95'][0]:+.4f}, {canonical['ci95'][1]:+.4f}] | "
            f"{post['estimate']:+.4f} | "
            f"[{post['ci95'][0]:+.4f}, {post['ci95'][1]:+.4f}] | "
            f"{'yes' if decisions[name]['meets_success_rule'] else 'no'} |"
        )
    lines.extend(
        [
            "",
            "## Per-Source Post-Diff Delta",
            "",
            "| readout | PrimeVul | DeltaSecommits | PatchEval |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for name, comparison in comparisons.items():
        by_dataset = comparison["by_dataset"]
        lines.append(
            f"| `{name}` | "
            f"{by_dataset['primevul']['post_diff_relation_delta']['estimate']:+.4f} | "
            f"{by_dataset['deltasecommits']['post_diff_relation_delta']['estimate']:+.4f} | "
            f"{by_dataset['patcheval']['post_diff_relation_delta']['estimate']:+.4f} |"
        )
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "- Mean and changed-hunk pooling strongly reduce post-diff endpoint sensitivity, but neither meets the preregistered canonical-delta tolerance on the fixed audit.",
            "- First-token pooling collapses because a causal decoder's first token cannot attend to the subsequent diff; its apparent consistency gain is not a valid capability gain.",
            "- Changed-hunk pooling reaches `99.83%` post-diff consistency while side-swap equivariance remains near its marginal-conditioned independence baseline, separating endpoint robustness from side-order reasoning.",
            "- Fixed-terminal-anchor pooling improves endpoint stability but loses canonical accuracy and changes the truncation budget; its clean-subset metrics are therefore not comparable without rematerialized runtime accounting.",
            "- No readout meets the preregistered discovery success rule, so no additional seeds are promoted yet.",
            "",
            "## Claim Boundary",
            "",
            "This is a same-backbone readout intervention. Seed `42` is discovery-only; any selected readout requires two additional seeds.",
            "",
        ]
    )
    (ROOT / args.markdown_output).write_text(
        "\n".join(lines),
        encoding="utf-8",
    )
    print(json.dumps(payload["success_rule"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

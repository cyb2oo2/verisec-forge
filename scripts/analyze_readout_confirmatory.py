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
from vrf.qwen_mechanism_analysis import join_predictions
from vrf.readout_confirmatory_analysis import (
    compare_confirmatory_models,
    summarize_confirmatory_rows,
)


def pct(value: float) -> str:
    return f"{100 * value:.2f}%"


def interval(row: dict) -> str:
    low, high = row["ci95"]
    return f"[{low:+.4f}, {high:+.4f}]"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze the independent readout confirmation study."
    )
    parser.add_argument(
        "--runtime",
        default=(
            "data/processed/"
            "secure_code_readout_confirmatory_v1_runtime512.jsonl"
        ),
    )
    parser.add_argument(
        "--predictions-template",
        default=(
            "outputs/secure_code_readout_confirmatory_"
            "{readout}_seed{seed}_predictions.jsonl"
        ),
    )
    parser.add_argument(
        "--json-output",
        default="reports/secure_code_readout_confirmatory_v1.json",
    )
    parser.add_argument(
        "--markdown-output",
        default="reports/READOUT_CONFIRMATORY.md",
    )
    parser.add_argument("--bootstrap-iterations", type=int, default=10000)
    parser.add_argument("--bootstrap-seed", type=int, default=20260613)
    args = parser.parse_args()

    runtime = read_jsonl(ROOT / args.runtime)
    summaries = {}
    records = {}
    for readout in ("terminal", "mean", "changed_hunk"):
        summaries[readout] = {}
        records[readout] = {}
        for seed in (7, 123):
            path = ROOT / args.predictions_template.format(
                readout=readout, seed=seed
            )
            joined = join_predictions(runtime, read_jsonl(path))
            summary = summarize_confirmatory_rows(joined)
            records[readout][seed] = summary["records"]
            summaries[readout][str(seed)] = {
                key: value
                for key, value in summary.items()
                if key != "records"
            }

    comparisons = {
        candidate: compare_confirmatory_models(
            records["terminal"],
            records[candidate],
            iterations=args.bootstrap_iterations,
            seed=args.bootstrap_seed,
        )
        for candidate in ("mean", "changed_hunk")
    }
    payload = {
        "status": "ok",
        "scope": "independent_same_backbone_readout_confirmation",
        "protocol": "docs/READOUT_CONFIRMATORY_PROTOCOL.md",
        "discovery_boundary": (
            "PR #8 pairs, suffix templates, and seed 42 are excluded."
        ),
        "seeds": [7, 123],
        "uncertainty_scope": {
            "bootstrap_unit": "held_out_pair",
            "seed_aggregation": "average_over_seeds_7_and_123",
            "interpretation": (
                "Pair-cluster bootstrap intervals quantify variation across "
                "held-out pairs after averaging seeds 7 and 123. They are "
                "conditional on these selected training seeds and do not "
                "estimate seed-population uncertainty."
            ),
            "seed_stability_check": (
                "Seed-wise effects are reported separately, and the "
                "confirmatory rule requires positive suffix deltas in both "
                "seeds."
            ),
        },
        "readouts": summaries,
        "paired_comparisons_vs_terminal": comparisons,
        "claim_boundary": (
            "This confirms readout-conditioned training behavior on new pair "
            "IDs and unseen suffixes. It does not isolate frozen-backbone "
            "pooling, and side-swap consistency is a separate endpoint."
        ),
    }
    write_json(ROOT / args.json_output, payload)

    lines = [
        "# Independent Readout Confirmation",
        "",
        "PR #8 is frozen as discovery. This study uses 180 new pair IDs, "
        "three unseen suffix templates, and training seeds 7 and 123.",
        "",
        "## Per-Seed Endpoints",
        "",
        "| readout | seed | canonical | macro suffix | swap | baseline | residual | both correct | visible | fallback |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for readout, by_seed in summaries.items():
        for seed, row in by_seed.items():
            lines.append(
                f"| `{readout}` | {seed} | "
                f"{pct(row['canonical_accuracy'])} | "
                f"{pct(row['macro_suffix_consistency'])} | "
                f"{pct(row['side_swap_equivariance'])} | "
                f"{pct(row['side_swap_independence_baseline'])} | "
                f"{row['side_swap_equivariance_residual']:+.4f} | "
                f"{pct(row['both_directions_correct'])} | "
                f"{pct(row['suffix_visible_pair_coverage'])} | "
                f"{pct(row['pooling_fallback_rate'])} |"
            )
    lines.extend(
        [
            "",
            "## Confirmatory Comparisons",
            "",
            "| candidate | canonical delta | 95% CI | suffix delta | 95% CI | both seeds positive | confirmed |",
            "| --- | ---: | --- | ---: | --- | --- | --- |",
        ]
    )
    for candidate, comparison in comparisons.items():
        pooled = comparison["pooled_pair_cluster"]
        canonical = pooled["canonical_accuracy_delta"]
        suffix = pooled["macro_suffix_consistency_delta"]
        rule = comparison["success_rule"]
        lines.append(
            f"| `{candidate}` | {canonical['estimate']:+.4f} | "
            f"{interval(canonical)} | {suffix['estimate']:+.4f} | "
            f"{interval(suffix)} | "
            f"{'yes' if rule['all_seed_suffix_deltas_positive'] else 'no'} | "
            f"{'yes' if rule['confirmed'] else 'no'} |"
        )
    lines.extend(
        [
            "",
            "## Per-Source Pooled Deltas",
            "",
            "| candidate | source | canonical delta | suffix delta | suffix 95% CI |",
            "| --- | --- | ---: | ---: | --- |",
        ]
    )
    for candidate, comparison in comparisons.items():
        for source, row in comparison["by_dataset"].items():
            suffix = row["macro_suffix_consistency_delta"]
            lines.append(
                f"| `{candidate}` | `{source}` | "
                f"{row['canonical_accuracy_delta']['estimate']:+.4f} | "
                f"{suffix['estimate']:+.4f} | {interval(suffix)} |"
            )
    lines.extend(
        [
            "",
            "Canonical non-inferiority uses all 180 pairs. The suffix endpoint "
            "uses only pairs where the intervention is visible after "
            "tokenization and truncation.",
            "",
            "Bootstrap intervals quantify variation across held-out pairs "
            "after averaging seeds 7 and 123. They are conditional on these "
            "two selected training seeds, not estimates of seed-population "
            "uncertainty; seed-wise effects are reported separately.",
            "",
            "## Interpretation",
            "",
        ]
    )
    confirmed = [
        name
        for name, row in comparisons.items()
        if row["success_rule"]["confirmed"]
    ]
    if confirmed:
        lines.append(
            "- Confirmed candidates under the preregistered rule: "
            + ", ".join(f"`{name}`" for name in confirmed)
            + "."
        )
    else:
        lines.append(
            "- Neither candidate meets all preregistered confirmation checks."
        )
    lines.extend(
        [
            "- Side-swap equivariance remains a separate relational failure; "
            "endpoint robustness must not be presented as solving side order.",
            "- Changed-hunk fallback and critical-hunk visibility are reported "
            "to expose implementation or truncation artifacts.",
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
                name: row["success_rule"]
                for name, row in comparisons.items()
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

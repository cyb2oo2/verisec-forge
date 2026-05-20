from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def read_json(path: str | Path) -> dict[str, Any]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def write_json(path: str | Path, payload: dict[str, Any]) -> None:
    output = ROOT / path
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def fmt(value: float) -> str:
    return f"{value:.4f}".rstrip("0").rstrip(".")


def find_feature(feature_payload: dict[str, Any], feature_mode: str) -> dict[str, Any]:
    for row in feature_payload["feature_results"]:
        if row["feature_mode"] == feature_mode:
            return row
    raise ValueError(f"Missing feature mode: {feature_mode}")


def leave_one_bounds(payload: dict[str, Any]) -> dict[str, Any]:
    deltas = {
        row["heldout_source"]: float(row["deltas"]["routed_minus_oracle"]["balanced_accuracy"])
        for row in payload["heldout_results"]
    }
    return {
        "deltas_vs_oracle_ba": deltas,
        "worst_delta_vs_oracle_ba": min(deltas.values()),
        "best_delta_vs_oracle_ba": max(deltas.values()),
    }


def build_report(
    *,
    stats_payload: dict[str, Any],
    leave_one_payload: dict[str, Any],
    feature_payload: dict[str, Any],
) -> dict[str, Any]:
    char_row = find_feature(feature_payload, "char_3_5")
    token_row = find_feature(feature_payload, "token_1_2")
    line_row = find_feature(feature_payload, "diff_line_markers")
    single_delta = stats_payload["deltas"]["single matched-mixed checkpoint"]["balanced_accuracy"]
    single_group_delta = stats_payload["deltas"]["single matched-mixed checkpoint"]["group_all_correct_rate"]
    leave_bounds = leave_one_bounds(leave_one_payload)
    return {
        "status": "ok",
        "scope": "learned_router_claim_boundary",
        "claim": (
            "Learned diff-body routing provides a small row-level system gain in a closed-world three-source setting, "
            "but group consistency and unseen-source routing remain bounded claims."
        ),
        "closed_world_statistical_support": {
            "learned_minus_single_ba": single_delta["observed_delta"],
            "learned_minus_single_ba_ci95": [single_delta["ci95_low"], single_delta["ci95_high"]],
            "learned_minus_single_ba_p_value": stats_payload["paired_tests"]["single matched-mixed checkpoint"]["balanced_accuracy"][
                "two_sided_p_value"
            ],
            "learned_minus_single_group_all_correct": single_group_delta["observed_delta"],
            "learned_minus_single_group_all_correct_ci95": [single_group_delta["ci95_low"], single_group_delta["ci95_high"]],
        },
        "feature_ablation": {
            "char_3_5": {
                "routing_row_accuracy": char_row["routing_metrics"]["row_accuracy"],
                "routed_ba": char_row["systems"][2]["overall"]["balanced_accuracy"],
                "delta_vs_single_ba": char_row["deltas"]["routed_minus_single"]["balanced_accuracy"],
            },
            "token_1_2": {
                "routing_row_accuracy": token_row["routing_metrics"]["row_accuracy"],
                "routed_ba": token_row["systems"][2]["overall"]["balanced_accuracy"],
                "delta_vs_single_ba": token_row["deltas"]["routed_minus_single"]["balanced_accuracy"],
            },
            "diff_line_markers": {
                "routing_row_accuracy": line_row["routing_metrics"]["row_accuracy"],
                "routed_ba": line_row["systems"][2]["overall"]["balanced_accuracy"],
                "delta_vs_single_ba": line_row["deltas"]["routed_minus_single"]["balanced_accuracy"],
            },
        },
        "leave_one_source_boundary": leave_bounds,
        "reviewer_facing_conclusion": (
            "The safest claim is closed-world source-aware expert selection. The row-level BA gain over a single matched-mixed checkpoint "
            "is statistically positive at the point estimate, weaker feature views preserve some system benefit, and leave-one-source stress "
            "prevents overclaiming unseen-source expert discovery."
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    stats = payload["closed_world_statistical_support"]
    feature = payload["feature_ablation"]
    leave = payload["leave_one_source_boundary"]
    lines = [
        "# Learned Router Claim Boundary",
        "",
        "This reviewer-facing summary consolidates the statistical, feature-ablation, and leave-one-source evidence for learned source/expert routing.",
        "",
        "## Main Claim",
        "",
        payload["claim"],
        "",
        "## Boundary Table",
        "",
        "| Check | Evidence | Reviewer-safe interpretation |",
        "| --- | --- | --- |",
        (
            "| Closed-world statistical support | "
            f"BA delta `{fmt(stats['learned_minus_single_ba'])}`, CI "
            f"`[{fmt(stats['learned_minus_single_ba_ci95'][0])}, {fmt(stats['learned_minus_single_ba_ci95'][1])}]`, "
            f"McNemar p `{stats['learned_minus_single_ba_p_value']}` | "
            "Small row-level gain over single matched-mixed baseline. |"
        ),
        (
            "| Group consistency | "
            f"group all-correct delta `{fmt(stats['learned_minus_single_group_all_correct'])}`, CI "
            f"`[{fmt(stats['learned_minus_single_group_all_correct_ci95'][0])}, {fmt(stats['learned_minus_single_group_all_correct_ci95'][1])}]` | "
            "Not statistically reliable; do not claim broad pair consistency gain. |"
        ),
        (
            "| Feature ablation | "
            f"char BA `{feature['char_3_5']['routed_ba']}`, token BA `{feature['token_1_2']['routed_ba']}`, "
            f"diff-line BA `{feature['diff_line_markers']['routed_ba']}` | "
            "System benefit is not exclusive to one char n-gram view, but char routing remains strongest. |"
        ),
        (
            "| Leave-one-source stress | "
            f"held-out routed-minus-oracle BA range `[{fmt(leave['worst_delta_vs_oracle_ba'])}, {fmt(leave['best_delta_vs_oracle_ba'])}]` | "
            "Closed-world adapter selection, not unseen-source expert discovery. |"
        ),
        "",
        "## Feature View Summary",
        "",
        "| Feature mode | Routing row accuracy | Routed BA | Delta vs single BA |",
        "| --- | ---: | ---: | ---: |",
    ]
    for mode, row in feature.items():
        lines.append(
            f"| `{mode}` | `{row['routing_row_accuracy']}` | `{row['routed_ba']}` | `{row['delta_vs_single_ba']}` |"
        )
    lines.extend(
        [
            "",
            "## Leave-One-Source Summary",
            "",
            "| Held-out source | Routed minus oracle BA |",
            "| --- | ---: |",
        ]
    )
    for source, delta in leave["deltas_vs_oracle_ba"].items():
        lines.append(f"| `{source}` | `{delta}` |")
    lines.extend(["", "## Conclusion", "", payload["reviewer_facing_conclusion"], ""])
    return "\n".join(lines)


def render_svg(payload: dict[str, Any]) -> str:
    feature = payload["feature_ablation"]
    bars = [
        ("char_3_5", float(feature["char_3_5"]["routed_ba"]), "#1f6f8b"),
        ("token_1_2", float(feature["token_1_2"]["routed_ba"]), "#d57a1f"),
        ("diff_line", float(feature["diff_line_markers"]["routed_ba"]), "#4f8f3a"),
    ]
    width = 760
    height = 300
    x0 = 180
    y0 = 70
    bar_h = 32
    gap = 28
    scale_min = 0.85
    scale_max = 0.87
    scale_w = 480

    def x_for(value: float) -> float:
        return x0 + (value - scale_min) / (scale_max - scale_min) * scale_w

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#fbfaf7"/>',
        '<text x="34" y="34" font-family="Arial, sans-serif" font-size="20" font-weight="700" fill="#24313a">Learned Router Claim Boundary</text>',
        '<text x="34" y="56" font-family="Arial, sans-serif" font-size="12" fill="#52616b">Routed-system balanced accuracy by feature view</text>',
        f'<line x1="{x0}" y1="238" x2="{x0 + scale_w}" y2="238" stroke="#9aa6ad" stroke-width="1"/>',
    ]
    for tick in [0.85, 0.855, 0.86, 0.865, 0.87]:
        x = x_for(tick)
        lines.append(f'<line x1="{x:.1f}" y1="232" x2="{x:.1f}" y2="244" stroke="#9aa6ad" stroke-width="1"/>')
        lines.append(
            f'<text x="{x - 14:.1f}" y="262" font-family="Arial, sans-serif" font-size="11" fill="#52616b">{tick:.3f}</text>'
        )
    for idx, (label, value, color) in enumerate(bars):
        y = y0 + idx * (bar_h + gap)
        x = x_for(value)
        lines.append(f'<text x="34" y="{y + 22}" font-family="Arial, sans-serif" font-size="13" fill="#24313a">{label}</text>')
        lines.append(f'<rect x="{x0}" y="{y}" width="{max(0, x - x0):.1f}" height="{bar_h}" fill="{color}" rx="5"/>')
        lines.append(
            f'<text x="{x + 8:.1f}" y="{y + 21}" font-family="Arial, sans-serif" font-size="12" font-weight="700" fill="#24313a">{value:.4f}</text>'
        )
    lines.append(
        '<text x="34" y="286" font-family="Arial, sans-serif" font-size="12" fill="#52616b">Boundary: group gain is non-significant; leave-one-source stress supports closed-world routing only.</text>'
    )
    lines.append("</svg>")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build learned-router claim-boundary summary report.")
    parser.add_argument("--stats", default="reports/secure_code_learned_content_routed_system_statistics_v1.json")
    parser.add_argument("--leave-one", default="reports/secure_code_learned_content_router_leave_one_source_v1.json")
    parser.add_argument("--feature-ablation", default="reports/secure_code_learned_content_router_feature_ablation_v1.json")
    parser.add_argument("--json-output", default="reports/secure_code_learned_router_claim_boundary_v1.json")
    parser.add_argument("--md-output", default="reports/LEARNED_ROUTER_CLAIM_BOUNDARY.md")
    parser.add_argument("--svg-output", default="reports/assets/learned_router_claim_boundary.svg")
    args = parser.parse_args()

    payload = build_report(
        stats_payload=read_json(args.stats),
        leave_one_payload=read_json(args.leave_one),
        feature_payload=read_json(args.feature_ablation),
    )
    write_json(args.json_output, payload)
    (ROOT / args.md_output).write_text(render_markdown(payload), encoding="utf-8")
    svg_path = ROOT / args.svg_output
    svg_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.write_text(render_svg(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

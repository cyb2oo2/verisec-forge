from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vrf.io_utils import read_json


def _x(value: float, *, left: int, width: int, domain: tuple[float, float]) -> float:
    low, high = domain
    return left + ((value - low) / (high - low)) * width


def render_svg(payload: dict[str, Any]) -> str:
    strict = payload["strict_pair_minus_bucket"]
    row_delta = strict["balanced_accuracy_delta"]
    group_delta = strict["group_all_correct_delta"]
    headline = payload["headline_pair_minus_diff_only"]
    diff = payload["diff_only_three_seed"]
    pair = payload["pair_coupled_multisplit"]
    tests = payload["paired_tests"]

    width = 1120
    height = 640
    left = 84
    chart_width = 760
    domain = (0.0, 0.14)
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="PrimeVul pair-coupled significance summary">',
        '<rect width="100%" height="100%" fill="#f8fafc"/>',
        '<text x="42" y="46" fill="#0f172a" font-family="Segoe UI, Arial, sans-serif" font-size="26" font-weight="750">Pair-Coupled Decoding: Statistical Support</text>',
        '<text x="42" y="76" fill="#475569" font-family="Segoe UI, Arial, sans-serif" font-size="14">Strict same-split deltas stay positive across split seeds; headline comparison is shown with protocol caveat.</text>',
    ]

    for tick in [0.0, 0.035, 0.07, 0.105, 0.14]:
        x = _x(tick, left=left, width=chart_width, domain=domain)
        lines.append(f'<line x1="{x:.1f}" y1="122" x2="{x:.1f}" y2="348" stroke="#e2e8f0" stroke-width="1"/>')
        lines.append(f'<text x="{x:.1f}" y="372" text-anchor="middle" fill="#64748b" font-family="Segoe UI, Arial, sans-serif" font-size="12">{tick:.3f}</text>')
    lines.append(f'<line x1="{left}" y1="348" x2="{left + chart_width}" y2="348" stroke="#cbd5e1" stroke-width="1"/>')

    rows = [
        ("Balanced accuracy delta", row_delta, "#db2777", strict["positive_balanced_accuracy_splits"]),
        ("Group all-correct delta", group_delta, "#0f766e", strict["positive_group_all_correct_splits"]),
    ]
    for index, (label, block, color, positive_splits) in enumerate(rows):
        y = 164 + index * 108
        mean = float(block["mean"])
        low = float(block["ci95_low"])
        high = float(block["ci95_high"])
        x_mean = _x(mean, left=left, width=chart_width, domain=domain)
        x_low = _x(low, left=left, width=chart_width, domain=domain)
        x_high = _x(high, left=left, width=chart_width, domain=domain)
        lines.extend(
            [
                f'<text x="42" y="{y - 22}" fill="#0f172a" font-family="Segoe UI, Arial, sans-serif" font-size="17" font-weight="700">{html.escape(label)}</text>',
                f'<line x1="{x_low:.1f}" y1="{y}" x2="{x_high:.1f}" y2="{y}" stroke="{color}" stroke-width="9" stroke-linecap="round"/>',
                f'<circle cx="{x_mean:.1f}" cy="{y}" r="13" fill="{color}" stroke="#ffffff" stroke-width="3"/>',
                f'<text x="{x_high + 18:.1f}" y="{y + 5}" fill="#0f172a" font-family="Segoe UI, Arial, sans-serif" font-size="15" font-weight="700">+{mean:.4f}</text>',
                f'<text x="{x_high + 96:.1f}" y="{y + 5}" fill="#64748b" font-family="Segoe UI, Arial, sans-serif" font-size="13">95% CI [{low:.4f}, {high:.4f}], {positive_splits}/{strict["total_splits"]} splits positive</text>',
            ]
        )

    card_y = 408
    card_w = 318
    cards = [
        ("Diff-only", f"{diff['mean']:.4f}", f"3 seeds; CI [{diff['ci95_low']:.4f}, {diff['ci95_high']:.4f}]", "#0f766e"),
        ("Pair-coupled", f"{pair['mean']:.4f}", f"5 splits; CI [{pair['ci95_low']:.4f}, {pair['ci95_high']:.4f}]", "#db2777"),
        ("Headline delta", f"+{headline['balanced_accuracy_delta']:.4f}", "Narrative comparison, not strict paired test", "#2563eb"),
    ]
    for index, (title, value, subtitle, color) in enumerate(cards):
        x = 42 + index * (card_w + 26)
        lines.extend(
            [
                f'<rect x="{x}" y="{card_y}" width="{card_w}" height="114" rx="20" fill="#ffffff" stroke="#e2e8f0"/>',
                f'<text x="{x + 22}" y="{card_y + 34}" fill="#475569" font-family="Segoe UI, Arial, sans-serif" font-size="14">{html.escape(title)}</text>',
                f'<text x="{x + 22}" y="{card_y + 72}" fill="{color}" font-family="Segoe UI, Arial, sans-serif" font-size="32" font-weight="750">{html.escape(value)}</text>',
                f'<text x="{x + 22}" y="{card_y + 96}" fill="#64748b" font-family="Segoe UI, Arial, sans-serif" font-size="12">{html.escape(subtitle)}</text>',
            ]
        )

    lines.extend(
        [
            '<text x="42" y="568" fill="#0f172a" font-family="Segoe UI, Arial, sans-serif" font-size="14" font-weight="700">Paired tests</text>',
            f'<text x="42" y="592" fill="#475569" font-family="Segoe UI, Arial, sans-serif" font-size="12">McNemar p-values: {html.escape(str(tests["row_mcnemar_p_values"]))}</text>',
            f'<text x="42" y="612" fill="#475569" font-family="Segoe UI, Arial, sans-serif" font-size="12">Group sign-test p-values: {html.escape(str(tests["group_all_correct_sign_p_values"]))}</text>',
            "</svg>",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an SVG chart for the PrimeVul pair-coupled significance report.")
    parser.add_argument("--input", default="reports/secure_code_primevul_pair_coupled_significance_v1.json")
    parser.add_argument("--output", default="reports/assets/primevul_pair_coupled_significance.svg")
    args = parser.parse_args()

    payload = read_json(args.input)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_svg(payload), encoding="utf-8")
    print(json.dumps({"output": str(output), "status": payload.get("status")}, indent=2))


if __name__ == "__main__":
    main()

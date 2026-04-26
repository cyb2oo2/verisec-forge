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


DISPLAY_ROWS = [
    "same-source detector on paired eval",
    "paired-trained snippet detector",
    "metadata-only control",
    "candidate-only control",
    "counterpart-only control",
    "pair-context detector",
    "candidate+diff detector",
    "diff-only detector, dedup eval",
    "diff-only detector, seed7 dedup",
    "diff-only detector, seed99 dedup",
]


def load_display_rows(results_path: str) -> list[dict[str, Any]]:
    payload = read_json(results_path)
    by_name = {row["system"]: row for row in payload["rows"]}
    return [by_name[name] for name in DISPLAY_ROWS]


def color_for(system: str) -> str:
    if "diff-only" in system:
        return "#0f766e"
    if "control" in system:
        return "#94a3b8"
    if "candidate+diff" in system or "pair-context" in system:
        return "#2563eb"
    return "#f97316"


def render_svg(rows: list[dict[str, Any]]) -> str:
    width = 980
    row_height = 44
    top = 92
    left_label = 290
    chart_width = 560
    height = top + row_height * len(rows) + 74
    axis_x = left_label
    axis_y = top + row_height * len(rows) + 16

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="PrimeVul paired benchmark results">',
        '<rect width="100%" height="100%" fill="#f8fafc"/>',
        '<text x="32" y="38" fill="#0f172a" font-family="Segoe UI, Arial, sans-serif" font-size="24" font-weight="700">PrimeVul Paired Benchmark: Patch/Diff Reasoning Wins</text>',
        '<text x="32" y="66" fill="#475569" font-family="Segoe UI, Arial, sans-serif" font-size="14">Balanced accuracy, generated from reports/PRIMEVUL_MAIN_RESULTS.json</text>',
    ]

    for tick in [0.5, 0.6, 0.7, 0.8]:
        x = axis_x + (tick * chart_width)
        lines.append(f'<line x1="{x:.1f}" y1="{top - 18}" x2="{x:.1f}" y2="{axis_y}" stroke="#e2e8f0" stroke-width="1"/>')
        lines.append(f'<text x="{x:.1f}" y="{axis_y + 22}" text-anchor="middle" fill="#64748b" font-family="Segoe UI, Arial, sans-serif" font-size="12">{tick:.1f}</text>')

    lines.append(f'<line x1="{axis_x}" y1="{axis_y}" x2="{axis_x + chart_width}" y2="{axis_y}" stroke="#cbd5e1" stroke-width="1"/>')

    for index, row in enumerate(rows):
        y = top + index * row_height
        value = float(row["balanced_accuracy"])
        bar_width = value * chart_width
        label = html.escape(row["system"])
        note = html.escape(row.get("note", ""))
        color = color_for(row["system"])
        lines.append(f'<text x="32" y="{y + 23}" fill="#0f172a" font-family="Segoe UI, Arial, sans-serif" font-size="13">{label}</text>')
        lines.append(f'<rect x="{axis_x}" y="{y + 8}" width="{bar_width:.1f}" height="22" rx="6" fill="{color}"/>')
        lines.append(f'<text x="{axis_x + bar_width + 8:.1f}" y="{y + 24}" fill="#0f172a" font-family="Segoe UI, Arial, sans-serif" font-size="13" font-weight="600">{value:.4f}</text>')
        lines.append(f'<text x="{axis_x + chart_width + 36}" y="{y + 24}" fill="#64748b" font-family="Segoe UI, Arial, sans-serif" font-size="12">{note}</text>')

    lines.append('<rect x="32" y="' + str(height - 38) + '" width="14" height="14" rx="3" fill="#94a3b8"/>')
    lines.append('<text x="52" y="' + str(height - 27) + '" fill="#475569" font-family="Segoe UI, Arial, sans-serif" font-size="12">negative controls</text>')
    lines.append('<rect x="190" y="' + str(height - 38) + '" width="14" height="14" rx="3" fill="#2563eb"/>')
    lines.append('<text x="210" y="' + str(height - 27) + '" fill="#475569" font-family="Segoe UI, Arial, sans-serif" font-size="12">comparison variants</text>')
    lines.append('<rect x="360" y="' + str(height - 38) + '" width="14" height="14" rx="3" fill="#0f766e"/>')
    lines.append('<text x="380" y="' + str(height - 27) + '" fill="#475569" font-family="Segoe UI, Arial, sans-serif" font-size="12">diff-only runs</text>')
    lines.append("</svg>")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an SVG bar chart for the PrimeVul main results.")
    parser.add_argument("--results", default="reports/PRIMEVUL_MAIN_RESULTS.json")
    parser.add_argument("--output", default="reports/assets/primevul_main_results.svg")
    args = parser.parse_args()

    rows = load_display_rows(args.results)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_svg(rows), encoding="utf-8")
    print(json.dumps({"output": str(output), "rows": len(rows)}, indent=2))


if __name__ == "__main__":
    main()

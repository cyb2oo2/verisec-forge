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
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from vrf.io_utils import read_json


COLORS = {
    "artifact": "#ef4444",
    "control": "#64748b",
    "system": "#0f766e",
    "audit": "#2563eb",
}

STAGE_KIND = {
    "Same-source baseline": "artifact",
    "Paired stress test": "artifact",
    "Shortcut controls": "control",
    "Paired diff detector": "system",
    "No-metadata check": "system",
    "Pair-coupled decoding": "system",
    "Evidence propagation": "audit",
    "Safe flip gate": "audit",
}


def wrap_text(text: str, max_chars: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    for word in words:
        candidate = " ".join([*current, word])
        if len(candidate) > max_chars and current:
            lines.append(" ".join(current))
            current = [word]
        else:
            current.append(word)
    if current:
        lines.append(" ".join(current))
    return lines


def kind_for_stage(stage: str) -> str:
    return STAGE_KIND.get(stage, "audit")


def render_svg(payload: dict[str, Any]) -> str:
    rows = payload["rows"]
    width = 1180
    top = 112
    row_height = 96
    left = 42
    timeline_x = 132
    card_x = 178
    card_width = 930
    height = top + row_height * len(rows) + 88
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="PrimeVul progressive controls chart">',
        '<rect width="100%" height="100%" fill="#f8fafc"/>',
        '<text x="42" y="42" fill="#0f172a" font-family="Segoe UI, Arial, sans-serif" font-size="26" font-weight="750">PrimeVul Progressive Controls</text>',
        '<text x="42" y="70" fill="#475569" font-family="Segoe UI, Arial, sans-serif" font-size="14">Shortcut diagnosis -> paired diff reasoning -> evidence-coupled audit loop</text>',
        f'<line x1="{timeline_x}" y1="{top - 24}" x2="{timeline_x}" y2="{top + row_height * (len(rows) - 1) + 24}" stroke="#cbd5e1" stroke-width="4" stroke-linecap="round"/>',
    ]

    for index, row in enumerate(rows, start=1):
        y = top + (index - 1) * row_height
        kind = kind_for_stage(row["stage"])
        color = COLORS[kind]
        stage = html.escape(row["stage"])
        question = html.escape(row["question"])
        metric = html.escape(row["key_metric"])
        value = float(row["value"])
        supporting = html.escape(row["supporting_metric"])
        interpretation_lines = wrap_text(row["interpretation"], 94)
        lines.extend(
            [
                f'<circle cx="{timeline_x}" cy="{y}" r="19" fill="{color}"/>',
                f'<text x="{timeline_x}" y="{y + 5}" text-anchor="middle" fill="#ffffff" font-family="Segoe UI, Arial, sans-serif" font-size="14" font-weight="700">{index}</text>',
                f'<rect x="{card_x}" y="{y - 38}" width="{card_width}" height="76" rx="18" fill="#ffffff" stroke="#e2e8f0"/>',
                f'<text x="{card_x + 22}" y="{y - 12}" fill="#0f172a" font-family="Segoe UI, Arial, sans-serif" font-size="17" font-weight="700">{stage}</text>',
                f'<text x="{card_x + 22}" y="{y + 12}" fill="#475569" font-family="Segoe UI, Arial, sans-serif" font-size="13">{question}</text>',
                f'<text x="{card_x + 472}" y="{y - 12}" fill="{color}" font-family="Segoe UI, Arial, sans-serif" font-size="22" font-weight="750">{value:.4f}</text>',
                f'<text x="{card_x + 472}" y="{y + 12}" fill="#475569" font-family="Segoe UI, Arial, sans-serif" font-size="12">{metric}; {supporting}</text>',
            ]
        )
        for offset, line in enumerate(interpretation_lines[:2]):
            lines.append(
                f'<text x="{card_x + 22}" y="{y + 32 + offset * 16}" fill="#64748b" font-family="Segoe UI, Arial, sans-serif" font-size="12">{html.escape(line)}</text>'
            )

    legend_y = height - 38
    legend_items = [("artifact/stress", "artifact"), ("negative control", "control"), ("system result", "system"), ("audit loop", "audit")]
    x = left
    for label, kind in legend_items:
        color = COLORS[kind]
        lines.append(f'<rect x="{x}" y="{legend_y - 12}" width="14" height="14" rx="4" fill="{color}"/>')
        lines.append(f'<text x="{x + 22}" y="{legend_y}" fill="#475569" font-family="Segoe UI, Arial, sans-serif" font-size="12">{label}</text>')
        x += 172
    lines.append("</svg>")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an SVG narrative chart for PrimeVul progressive controls.")
    parser.add_argument("--input", default="reports/PRIMEVUL_PROGRESSIVE_CONTROLS.json")
    parser.add_argument("--output", default="reports/assets/primevul_progressive_controls.svg")
    args = parser.parse_args()

    payload = read_json(args.input)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_svg(payload), encoding="utf-8")
    print(json.dumps({"output": str(output), "rows": len(payload["rows"])}, indent=2))


if __name__ == "__main__":
    main()

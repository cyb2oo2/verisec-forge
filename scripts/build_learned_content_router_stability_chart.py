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


def fmt(value: float) -> str:
    return f"{value:.4f}".rstrip("0").rstrip(".")


def feature_label(feature_mode: str) -> str:
    labels = {
        "char_3_5": "char n-grams",
        "token_1_2": "token n-grams",
        "diff_line_markers": "diff-line markers",
    }
    return labels.get(feature_mode, feature_mode)


def extract_rows(payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for payload in payloads:
        feature_mode = str(payload["protocol"]["feature_mode"])
        for fraction in ["0.5", "1.0"]:
            summary = payload["summary_by_train_fraction"][fraction]
            rows.append(
                {
                    "feature_mode": feature_mode,
                    "label": feature_label(feature_mode),
                    "train_fraction": fraction,
                    "routed_ba_mean": float(summary["learned_ba"]["mean"]),
                    "routed_ba_min": float(summary["learned_ba"]["min"]),
                    "routed_ba_max": float(summary["learned_ba"]["max"]),
                    "route_accuracy_mean": float(summary["routing_row_accuracy"]["mean"]),
                    "group_all_correct_mean": float(summary["learned_group_all_correct"]["mean"]),
                }
            )
    return rows


def render_svg(rows: list[dict[str, Any]], *, single_ba: float = 0.8591, oracle_ba: float = 0.8664) -> str:
    width = 980
    height = 560
    plot_x = 248
    plot_y = 96
    plot_w = 600
    row_gap = 72
    bar_h = 18
    scale_min = 0.858
    scale_max = 0.867
    colors = {"0.5": "#1f6f8b", "1.0": "#d57a1f"}

    def x_for(value: float) -> float:
        return plot_x + (value - scale_min) / (scale_max - scale_min) * plot_w

    def safe_width(value: float) -> float:
        return max(0.0, x_for(value) - plot_x)

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="Learned content router stability chart">',
        '<rect width="100%" height="100%" fill="#fbfaf7"/>',
        '<text x="36" y="38" font-family="Segoe UI, Arial, sans-serif" font-size="24" font-weight="700" fill="#24313a">Learned Router Robustness</text>',
        '<text x="36" y="64" font-family="Segoe UI, Arial, sans-serif" font-size="13" fill="#52616b">Routed-system balanced accuracy under multi-seed pair-group subsampling</text>',
    ]
    for value, label, color in [(single_ba, "single matched-mixed", "#8a96a0"), (oracle_ba, "oracle source-routed", "#334155")]:
        x = x_for(value)
        lines.extend(
            [
                f'<line x1="{x:.1f}" y1="{plot_y - 20}" x2="{x:.1f}" y2="{plot_y + row_gap * 3}" stroke="{color}" stroke-width="1.5" stroke-dasharray="5 5"/>',
                f'<text x="{x + 6:.1f}" y="{plot_y - 27}" font-family="Segoe UI, Arial, sans-serif" font-size="11" fill="{color}">{label}: {fmt(value)}</text>',
            ]
        )
    for tick in [0.858, 0.86, 0.862, 0.864, 0.866]:
        x = x_for(tick)
        lines.append(f'<line x1="{x:.1f}" y1="{plot_y - 8}" x2="{x:.1f}" y2="{plot_y + row_gap * 3}" stroke="#e3e7ea" stroke-width="1"/>')
        lines.append(f'<text x="{x - 13:.1f}" y="{plot_y + row_gap * 3 + 24}" font-family="Segoe UI, Arial, sans-serif" font-size="11" fill="#64748b">{tick:.3f}</text>')

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["feature_mode"], []).append(row)
    feature_order = ["char_3_5", "token_1_2", "diff_line_markers"]
    for idx, feature in enumerate(feature_order):
        feature_rows = sorted(grouped[feature], key=lambda item: item["train_fraction"])
        y_base = plot_y + idx * row_gap
        lines.append(
            f'<text x="36" y="{y_base + 24}" font-family="Segoe UI, Arial, sans-serif" font-size="14" font-weight="700" fill="#24313a">{feature_label(feature)}</text>'
        )
        for bar_idx, row in enumerate(feature_rows):
            y = y_base + 4 + bar_idx * 24
            value = row["routed_ba_mean"]
            color = colors[row["train_fraction"]]
            lines.append(f'<rect x="{plot_x}" y="{y}" width="{safe_width(value):.1f}" height="{bar_h}" fill="{color}" rx="5"/>')
            lines.append(
                f'<text x="{x_for(value) + 8:.1f}" y="{y + 14}" font-family="Segoe UI, Arial, sans-serif" font-size="12" font-weight="700" fill="#24313a">{fmt(value)}</text>'
            )
            lines.append(
                f'<text x="{plot_x - 58}" y="{y + 14}" font-family="Segoe UI, Arial, sans-serif" font-size="12" fill="#52616b">{row["train_fraction"]} train</text>'
            )
    legend_y = height - 88
    lines.extend(
        [
            f'<rect x="36" y="{legend_y}" width="14" height="14" fill="{colors["0.5"]}" rx="3"/>',
            f'<text x="58" y="{legend_y + 12}" font-family="Segoe UI, Arial, sans-serif" font-size="12" fill="#52616b">50% train pairs, 3 seeds</text>',
            f'<rect x="226" y="{legend_y}" width="14" height="14" fill="{colors["1.0"]}" rx="3"/>',
            f'<text x="248" y="{legend_y + 12}" font-family="Segoe UI, Arial, sans-serif" font-size="12" fill="#52616b">100% train pairs, deterministic full set</text>',
            f'<text x="36" y="{height - 32}" font-family="Segoe UI, Arial, sans-serif" font-size="12" fill="#52616b">Interpretation: robust small BA gain across feature views; group consistency and open-set routing remain bounded claims.</text>',
            "</svg>",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build learned content-router stability SVG chart.")
    parser.add_argument("--char", default="reports/secure_code_learned_content_router_stability_char_v1.json")
    parser.add_argument("--token", default="reports/secure_code_learned_content_router_stability_token_v1.json")
    parser.add_argument("--diff-line", default="reports/secure_code_learned_content_router_stability_v1.json")
    parser.add_argument("--output", default="reports/assets/learned_content_router_stability.svg")
    args = parser.parse_args()

    rows = extract_rows([read_json(args.char), read_json(args.token), read_json(args.diff_line)])
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_svg(rows), encoding="utf-8")
    print(json.dumps({"status": "ok", "output": args.output, "rows": len(rows)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

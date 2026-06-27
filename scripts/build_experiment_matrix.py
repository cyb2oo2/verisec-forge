from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def _escape_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def load_registry(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def render_matrix(registry: dict[str, Any]) -> str:
    layer_order = registry["layer_order"]
    order_index = {layer: index for index, layer in enumerate(layer_order)}
    experiments = sorted(
        registry["experiments"],
        key=lambda item: (order_index[item["layer"]], item["id"]),
    )

    lines = [
        "# Experiment Matrix",
        "",
        "This matrix is generated from `experiments/registry.json` by",
        "`scripts/build_experiment_matrix.py`. It summarizes retained artifacts",
        "and their claim boundaries; it does not introduce new results.",
        "",
        "| Layer | Experiment | Primary Artifact | Claim | Boundary | Reproducibility |",
        "| --- | --- | --- | --- | --- | --- |",
    ]

    for item in experiments:
        artifact_target = f"../{item['primary_report']}"
        artifact = f"[{item['primary_report']}]({artifact_target})"
        lines.append(
            "| "
            + " | ".join(
                [
                    _escape_cell(item["layer"]),
                    _escape_cell(item["title"]),
                    artifact,
                    _escape_cell(item["claim"]),
                    _escape_cell(item["boundary"]),
                    _escape_cell(item["reproducibility"]),
                ]
            )
            + " |"
        )

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--registry",
        default="experiments/registry.json",
        help="Path to the experiment registry.",
    )
    parser.add_argument(
        "--output",
        default="reports/EXPERIMENT_MATRIX.md",
        help="Path to write the generated matrix.",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Fail if the generated matrix differs from the checked-in file.",
    )
    args = parser.parse_args()

    registry_path = ROOT / args.registry
    output_path = ROOT / args.output
    rendered = render_matrix(load_registry(registry_path))

    if args.check_only:
        existing = output_path.read_text(encoding="utf-8")
        if existing != rendered:
            raise SystemExit(f"{args.output} is out of date")
        return 0

    output_path.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

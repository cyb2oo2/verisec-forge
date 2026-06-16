from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_json
from vrf.reproducibility import count_jsonl_rows, sha256_file


def entry(role: str, path: str) -> dict[str, Any]:
    full_path = ROOT / path
    if not full_path.exists():
        raise FileNotFoundError(path)
    row: dict[str, Any] = {
        "role": role,
        "path": path,
        "sha256": sha256_file(full_path),
        "bytes": full_path.stat().st_size,
    }
    if full_path.suffix == ".jsonl":
        row["rows"] = count_jsonl_rows(full_path)
    return row


def build_manifest() -> dict[str, Any]:
    config = read_json(
        ROOT
        / "configs/research_frozen_backbone_readout_control_qwen15b_v1.json"
    )
    report_path = "reports/secure_code_frozen_backbone_readout_control_v1.json"
    report = read_json(ROOT / report_path)
    artifacts = [
        entry("train_feature_cache", config["train_cache"]),
        entry("confirm_feature_cache", config["confirm_cache"]),
    ]
    generated = [
        entry("train_cache_report", config["train_cache_report"]),
        entry("confirm_cache_report", config["confirm_cache_report"]),
        entry("control_report_json", report_path),
        entry(
            "control_report_markdown",
            "reports/FROZEN_BACKBONE_READOUT_CONTROL.md",
        ),
    ]
    for readout in ("terminal", "mean", "changed_hunk"):
        for seed in (7, 123):
            values = {"readout": readout, "seed": seed}
            artifacts.extend(
                [
                    entry(
                        f"{readout}_seed{seed}_predictions",
                        config["predictions_template"].format(**values),
                    ),
                    entry(
                        f"{readout}_seed{seed}_head",
                        config["head_template"].format(**values),
                    ),
                ]
            )
            generated.append(
                entry(
                    f"{readout}_seed{seed}_training_report",
                    config["training_report_template"].format(**values),
                )
            )
    expected = {
        candidate: {
            "pooled_pair_cluster": comparison["pooled_pair_cluster"],
            "mechanism_decision": comparison["mechanism_decision"],
        }
        for candidate, comparison in report[
            "comparisons_vs_terminal"
        ].items()
    }
    return {
        "name": "frozen_backbone_readout_control_v1",
        "description": (
            "Frozen Qwen+LoRA hidden representations, matched linear heads, "
            "predictions, and reports for the direct readout mechanism control."
        ),
        "created_utc": "2026-06-14",
        "analysis_command": [
            ".venv/Scripts/python.exe",
            "scripts/analyze_frozen_readout_control.py",
        ],
        "training_command": [
            ".venv/Scripts/python.exe",
            "scripts/train_frozen_readout_heads.py",
        ],
        "artifacts": artifacts,
        "generated_artifacts": generated,
        "expected": expected,
        "limitations": [
            "The bundle reproduces matched-head training and analysis from cached frozen representations.",
            "The 1.5B backbone checkpoint is not included; regenerating feature caches requires the recorded base revision and LoRA adapter.",
            "The control isolates pooling over one terminal-trained Qwen representation and does not establish broad model-family generality.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the frozen-readout control manifest."
    )
    parser.add_argument(
        "--output",
        default=(
            "reproducibility/"
            "frozen_backbone_readout_control_manifest.json"
        ),
    )
    args = parser.parse_args()
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(build_manifest(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"status": "ok", "output": args.output}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

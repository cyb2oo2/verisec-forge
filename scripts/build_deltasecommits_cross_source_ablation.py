from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


SYSTEMS = [
    {
        "name": "PrimeVul zero-shot",
        "training": "PrimeVul time-disjoint only",
        "report": "reports/secure_code_deltasecommits_eval_zero_shot_primevul_time_checkpoint_v1.json",
        "threshold_sweep": "",
        "note": "No DeltaSecommits training; fair eval-split slice of the external transfer run.",
    },
    {
        "name": "Delta-only",
        "training": "DeltaSecommits C/C++ train",
        "report": "reports/secure_code_deltasecommits_delta_only_pair_diff_eval_v1.json",
        "threshold_sweep": "reports/secure_code_deltasecommits_cls_qwen15bcoder_lora_pair_diff_cpp_v1_threshold_sweep.json",
        "note": "Source-specific adaptation baseline.",
    },
    {
        "name": "PrimeVul+Delta mixed",
        "training": "PrimeVul time-disjoint + DeltaSecommits C/C++ train",
        "report": "reports/secure_code_deltasecommits_mixed_primevul_time_delta_pair_diff_eval_v1.json",
        "threshold_sweep": "reports/secure_code_mixed_primevul_time_deltasecommits_cls_qwen15bcoder_lora_pair_diff_v1_delta_threshold_sweep.json",
        "note": "Full mixed-source training; tests whether adding PrimeVul helps Delta beyond Delta-only.",
    },
    {
        "name": "PrimeVul-short+Delta matched",
        "training": "Short PrimeVul time-disjoint + DeltaSecommits C/C++ train",
        "report": "reports/secure_code_deltasecommits_matched_mixed_primevul_time_short_delta_pair_diff_eval_v1.json",
        "threshold_sweep": "reports/secure_code_matched_mixed_primevul_time_short_deltasecommits_cls_qwen15bcoder_lora_pair_diff_v1_delta_threshold_sweep.json",
        "note": "Matched/short mixed-source training removes the PrimeVul extreme prompt-length tail before mixing.",
    },
]


def read_json(path: str) -> dict[str, Any]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def best_threshold(path: str) -> dict[str, Any] | None:
    if not path:
        return None
    payload = read_json(path)
    return payload["best_by_balanced_accuracy"]


def row_payload(system: dict[str, str]) -> dict[str, Any]:
    report = read_json(system["report"])
    default = report["default_threshold"]["overall"]
    default_group = report["default_threshold"]["group_metrics"]
    pair = report["pair_coupled"]["overall"]
    pair_group = report["pair_coupled"]["group_metrics"]
    threshold = best_threshold(system["threshold_sweep"])
    return {
        "system": system["name"],
        "training": system["training"],
        "rows": report["split"]["rows"],
        "pairs": report["split"]["unique_pair_count"],
        "default_balanced_accuracy": default["balanced_accuracy"],
        "default_recall": default["vulnerable_recall"],
        "default_specificity": default["safe_specificity"],
        "default_group_all_correct": default_group["group_all_correct_rate"],
        "pair_coupled_balanced_accuracy": pair["balanced_accuracy"],
        "pair_coupled_group_all_correct": pair_group["group_all_correct_rate"],
        "orientation_accuracy": pair_group["orientation_accuracy"],
        "best_threshold_balanced_accuracy": None if threshold is None else threshold["balanced_accuracy"],
        "best_threshold": None if threshold is None else threshold["threshold"],
        "note": system["note"],
    }


def fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.4f}" if isinstance(value, float) else str(value)


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# DeltaSecommits Cross-Source Ablation",
        "",
        "This report compares matched DeltaSecommits eval-split settings. It is the project first true second-source paired-patch validation table.",
        "",
        "## Results",
        "",
        "| System | Training data | Rows/Pairs | Default BA | Recall | Specificity | Pair-Coupled BA | Group All-Correct | Orientation | Best Threshold BA |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in payload["systems"]:
        lines.append(
            f"| `{row['system']}` | {row['training']} | `{row['rows']}/{row['pairs']}` | "
            f"`{fmt(row['default_balanced_accuracy'])}` | `{fmt(row['default_recall'])}` | "
            f"`{fmt(row['default_specificity'])}` | `{fmt(row['pair_coupled_balanced_accuracy'])}` | "
            f"`{fmt(row['pair_coupled_group_all_correct'])}` | `{fmt(row['orientation_accuracy'])}` | "
            f"`{fmt(row['best_threshold_balanced_accuracy'])}` |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- PrimeVul zero-shot remains strong on a second paired-patch source, especially after pair-coupled decoding.",
            "- Delta-only training improves the default detector slightly, but not by a large margin, which supports cross-source transfer rather than pure dataset memorization.",
            "- Full PrimeVul+Delta mixed training does not materially beat Delta-only on Delta eval, which argues against indiscriminate source mixing.",
            "- Matched/short mixed-source training improves the calibrated single-row operating point, but it still does not beat Delta-only on pair-coupled consistency; the next useful direction is domain-aware mixing/adapters rather than simply adding more source rows.",
            "",
            "## Notes",
            "",
        ]
    )
    for row in payload["systems"]:
        lines.append(f"- `{row['system']}`: {row['note']}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    systems = [row_payload(system) for system in SYSTEMS]
    payload = {
        "status": "ok",
        "scope": "deltasecommits_cross_source_ablation",
        "systems": systems,
        "conclusion": (
            "Second-source DeltaSecommits validation supports the paired-diff transfer story. "
            "Matched/short source mixing improves threshold-calibrated Delta accuracy, but Delta-only remains the best pair-coupled consistency baseline."
        ),
    }
    json_path = ROOT / "reports/secure_code_deltasecommits_cross_source_ablation_v1.json"
    md_path = ROOT / "reports/DELTASECCOMMITS_CROSS_SOURCE_ABLATION.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

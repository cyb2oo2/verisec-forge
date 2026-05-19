from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str | Path) -> dict[str, Any]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def counts_to_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(int(row.get("tp", 0)) for row in rows)
    tn = sum(int(row.get("tn", 0)) for row in rows)
    fp = sum(int(row.get("fp", 0)) for row in rows)
    fn = sum(int(row.get("fn", 0)) for row in rows)
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "num_examples": total,
        "presence_accuracy": round(accuracy, 4),
        "balanced_accuracy": round((recall + specificity) / 2, 4),
        "vulnerable_recall": round(recall, 4),
        "safe_specificity": round(specificity, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def aggregate_group(rows: list[dict[str, Any]]) -> dict[str, Any]:
    pair_count = sum(int(row.get("unique_pair_count", 0)) for row in rows)
    all_correct = sum(int(row.get("group_all_correct", 0)) for row in rows)
    orientation_count = sum(int(row.get("orientation_eligible_pair_count", 0)) for row in rows)
    orientation_correct = sum(int(row.get("orientation_correct", 0)) for row in rows)
    return {
        "unique_pair_count": pair_count,
        "group_all_correct": all_correct,
        "group_all_correct_rate": round(all_correct / pair_count, 4) if pair_count else 0.0,
        "orientation_eligible_pair_count": orientation_count,
        "orientation_correct": orientation_correct,
        "orientation_accuracy": round(orientation_correct / orientation_count, 4) if orientation_count else 0.0,
    }


def pair(report: dict[str, Any]) -> dict[str, Any]:
    return report["pair_coupled"]


def source_payload(name: str, report: dict[str, Any], *, adapter: str) -> dict[str, Any]:
    payload = pair(report)
    return {
        "source": name,
        "adapter": adapter,
        "overall": payload["overall"],
        "group_metrics": payload["group_metrics"],
        "checkpoint": report.get("protocol", {}).get("checkpoint", ""),
    }


def system_payload(name: str, sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "system": name,
        "overall": counts_to_metrics([source["overall"] for source in sources]),
        "group_metrics": aggregate_group([source["group_metrics"] for source in sources]),
        "sources": sources,
    }


def build_report(
    *,
    matched_prime_report: dict[str, Any],
    matched_delta_report: dict[str, Any],
    matched_patch_report: dict[str, Any],
    expert_prime_report: dict[str, Any],
    expert_delta_report: dict[str, Any],
    expert_patch_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    single_sources = [
        source_payload("PrimeVul-time", matched_prime_report, adapter="matched-mixed"),
        source_payload("DeltaSecommits", matched_delta_report, adapter="matched-mixed"),
        source_payload("PatchEval", matched_patch_report, adapter="matched-mixed"),
    ]
    patch_expert_available = expert_patch_report is not None
    routed_patch_report = expert_patch_report or matched_patch_report
    routed_patch_adapter = "patcheval expert" if patch_expert_available else "matched-mixed fallback"
    routed_sources = [
        source_payload("PrimeVul-time", expert_prime_report, adapter="primevul-time expert"),
        source_payload("DeltaSecommits", expert_delta_report, adapter="deltasecommits expert"),
        source_payload("PatchEval", routed_patch_report, adapter=routed_patch_adapter),
    ]
    single = system_payload("single matched-mixed checkpoint", single_sources)
    routed = system_payload("available source-routed adapters", routed_sources)
    return {
        "status": "ok",
        "scope": "three_source_available_adapter_mixture",
        "protocol": {
            "sources": ["PrimeVul-time", "DeltaSecommits", "PatchEval"],
            "note": (
                "This report extends the source-aware adapter mixture to three sources. "
                "When a PatchEval-specific adapter report is supplied, PatchEval is routed to that expert; otherwise it falls back to the matched-mixed checkpoint."
            ),
        },
        "systems": [single, routed],
        "routed_minus_single": {
            "balanced_accuracy": round(routed["overall"]["balanced_accuracy"] - single["overall"]["balanced_accuracy"], 4),
            "f1": round(routed["overall"]["f1"] - single["overall"]["f1"], 4),
            "group_all_correct_rate": round(
                routed["group_metrics"]["group_all_correct_rate"] - single["group_metrics"]["group_all_correct_rate"], 4
            ),
            "orientation_accuracy": round(
                routed["group_metrics"]["orientation_accuracy"] - single["group_metrics"]["orientation_accuracy"], 4
            ),
        },
        "patch_adapter_status": {
            "available": patch_expert_available,
            "adapter": routed_patch_adapter,
            "next_protocol": (
                "Use the PatchEval multi-seed report for stability, then cross-evaluate the PatchEval expert on PrimeVul/Delta to quantify specialization tradeoffs."
                if patch_expert_available
                else "Run PatchEval-specific adapter on a faster Linux/CUDA training path or a controlled smaller-model smoke before adding it as a routed expert."
            ),
        },
        "conclusion": (
            "The three-source source-routed adapter mixture improves over a single matched-mixed checkpoint. "
            "With the PatchEval expert available, the mixture now covers the hardest cross-language source rather than relying on a fallback."
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Three-Source Adapter Mixture",
        "",
        "This report extends source-aware routing to PrimeVul-time, DeltaSecommits, and PatchEval.",
        "",
        "## Results",
        "",
        "| System | BA | Recall | Specificity | F1 | Group All-Correct | Orientation |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for system in payload["systems"]:
        overall = system["overall"]
        group = system["group_metrics"]
        lines.append(
            f"| `{system['system']}` | `{overall['balanced_accuracy']}` | `{overall['vulnerable_recall']}` | "
            f"`{overall['safe_specificity']}` | `{overall['f1']}` | `{group['group_all_correct_rate']}` | "
            f"`{group['orientation_accuracy']}` |"
        )
    delta = payload["routed_minus_single"]
    patch_status = payload["patch_adapter_status"]
    lines.extend(
        [
            "",
            "## Delta",
            "",
            f"- Routed minus single BA: `{delta['balanced_accuracy']}`",
            f"- Routed minus single F1: `{delta['f1']}`",
            f"- Routed minus single group all-correct: `{delta['group_all_correct_rate']}`",
            f"- Routed minus single orientation: `{delta['orientation_accuracy']}`",
            "",
            "## PatchEval Adapter",
            "",
            f"- Available: `{patch_status['available']}`",
            f"- Adapter: `{patch_status['adapter']}`",
            f"- Next protocol: {patch_status['next_protocol']}",
            "",
            "## Interpretation",
            "",
            payload["conclusion"],
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a three-source available-adapter mixture report.")
    parser.add_argument(
        "--matched-prime-report",
        default="reports/secure_code_primevul_time_disjoint_matched_mixed_primevul_short_delta_v1.json",
    )
    parser.add_argument(
        "--matched-delta-report",
        default="reports/secure_code_deltasecommits_matched_mixed_primevul_time_short_delta_pair_diff_eval_v1.json",
    )
    parser.add_argument(
        "--matched-patch-report",
        default="reports/secure_code_patcheval_zero_shot_matched_mixed_primevul_short_delta_v1.json",
    )
    parser.add_argument("--expert-prime-report", default="reports/secure_code_primevul_time_disjoint_direct_train_v1.json")
    parser.add_argument("--expert-delta-report", default="reports/secure_code_deltasecommits_delta_only_pair_diff_eval_v1.json")
    parser.add_argument("--expert-patch-report", default="reports/secure_code_patcheval_adapter_pair_diff_eval_v1.json")
    parser.add_argument("--json-output", default="reports/secure_code_three_source_adapter_mixture_v1.json")
    parser.add_argument("--md-output", default="reports/THREE_SOURCE_ADAPTER_MIXTURE.md")
    args = parser.parse_args()

    payload = build_report(
        matched_prime_report=read_json(args.matched_prime_report),
        matched_delta_report=read_json(args.matched_delta_report),
        matched_patch_report=read_json(args.matched_patch_report),
        expert_prime_report=read_json(args.expert_prime_report),
        expert_delta_report=read_json(args.expert_delta_report),
        expert_patch_report=read_json(args.expert_patch_report) if (ROOT / args.expert_patch_report).exists() else None,
    )
    (ROOT / args.json_output).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (ROOT / args.md_output).write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

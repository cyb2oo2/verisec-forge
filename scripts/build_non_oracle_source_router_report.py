from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_three_source_adapter_mixture_report import aggregate_group, counts_to_metrics, source_payload, system_payload


def read_json(path: str | Path) -> dict[str, Any]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    with (ROOT / path).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def infer_source_without_label(row: dict[str, Any]) -> str:
    """Route by visible metadata shape, not by source_dataset/id/pair_key labels."""
    if row.get("programming_language") or row.get("patch_url") or row.get("vul_patch") or row.get("file_path"):
        return "PatchEval"
    extension = str(row.get("file_extension") or "").lower().lstrip(".")
    if extension in {"c", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx"}:
        return "DeltaSecommits"
    if row.get("time_disjoint_split") or row.get("cve_year") or row.get("file_name") or row.get("file_hash"):
        return "PrimeVul-time"
    return "unknown"


def routing_rows(metadata_by_source: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for true_source, metadata_rows in metadata_by_source.items():
        for row in metadata_rows:
            rows.append(
                {
                    "true_source": true_source,
                    "predicted_source": infer_source_without_label(row),
                    "pair_key": str(row.get("pair_key") or row.get("id")),
                }
            )
    return rows


def routing_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    correct = sum(1 for row in rows if row["true_source"] == row["predicted_source"])
    confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    by_source: dict[str, dict[str, int]] = defaultdict(lambda: {"rows": 0, "correct": 0})
    pair_votes: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for row in rows:
        confusion[row["true_source"]][row["predicted_source"]] += 1
        by_source[row["true_source"]]["rows"] += 1
        by_source[row["true_source"]]["correct"] += int(row["true_source"] == row["predicted_source"])
        pair_votes[(row["true_source"], row["pair_key"])][row["predicted_source"]] += 1
    pair_total = len(pair_votes)
    pair_correct = 0
    for (true_source, _pair_key), votes in pair_votes.items():
        predicted_source, _count = votes.most_common(1)[0]
        pair_correct += int(predicted_source == true_source)
    return {
        "row_count": total,
        "row_accuracy": round(correct / total, 4) if total else 0.0,
        "pair_group_count": pair_total,
        "pair_group_accuracy": round(pair_correct / pair_total, 4) if pair_total else 0.0,
        "confusion": {source: dict(predicted) for source, predicted in sorted(confusion.items())},
        "by_source": {
            source: {
                "rows": values["rows"],
                "correct": values["correct"],
                "accuracy": round(values["correct"] / values["rows"], 4) if values["rows"] else 0.0,
            }
            for source, values in sorted(by_source.items())
        },
    }


def routed_system_from_mapping(name: str, mapping: dict[str, dict[str, Any]], adapters: dict[str, str]) -> dict[str, Any]:
    sources = [source_payload(source, report, adapter=adapters[source]) for source, report in mapping.items()]
    return system_payload(name, sources)


def build_report(
    *,
    prime_metadata: list[dict[str, Any]],
    delta_metadata: list[dict[str, Any]],
    patch_metadata: list[dict[str, Any]],
    matched_prime_report: dict[str, Any],
    matched_delta_report: dict[str, Any],
    matched_patch_report: dict[str, Any],
    expert_prime_report: dict[str, Any],
    expert_delta_report: dict[str, Any],
    expert_patch_report: dict[str, Any],
) -> dict[str, Any]:
    metadata_by_source = {
        "PrimeVul-time": prime_metadata,
        "DeltaSecommits": delta_metadata,
        "PatchEval": patch_metadata,
    }
    rows = routing_rows(metadata_by_source)
    route_metrics = routing_metrics(rows)
    matched_mapping = {
        "PrimeVul-time": matched_prime_report,
        "DeltaSecommits": matched_delta_report,
        "PatchEval": matched_patch_report,
    }
    expert_mapping = {
        "PrimeVul-time": expert_prime_report,
        "DeltaSecommits": expert_delta_report,
        "PatchEval": expert_patch_report,
    }
    single = routed_system_from_mapping(
        "single matched-mixed checkpoint",
        matched_mapping,
        {source: "matched-mixed" for source in matched_mapping},
    )
    oracle = routed_system_from_mapping(
        "oracle source-routed experts",
        expert_mapping,
        {
            "PrimeVul-time": "primevul-time expert",
            "DeltaSecommits": "deltasecommits expert",
            "PatchEval": "patcheval expert",
        },
    )
    if route_metrics["row_accuracy"] == 1.0:
        automatic = routed_system_from_mapping(
            "non-oracle metadata-schema router",
            expert_mapping,
            {
                "PrimeVul-time": "primevul-time expert",
                "DeltaSecommits": "deltasecommits expert",
                "PatchEval": "patcheval expert",
            },
        )
        routing_note = "The metadata-schema router exactly matches the oracle source assignment on this three-source benchmark."
    else:
        automatic = {
            "system": "non-oracle metadata-schema router",
            "overall": counts_to_metrics([]),
            "group_metrics": aggregate_group([]),
            "sources": [],
        }
        routing_note = "The metadata-schema router is imperfect; per-row routed predictions are required before reporting system metrics."
    return {
        "status": "ok",
        "scope": "non_oracle_source_router",
        "protocol": {
            "router": "metadata-schema router",
            "forbidden_fields": ["source_dataset", "id", "pair_key"],
            "routing_features": {
                "PatchEval": ["programming_language", "patch_url", "vul_patch", "file_path"],
                "DeltaSecommits": ["file_extension in C/C++ family"],
                "PrimeVul-time": ["time_disjoint_split", "cve_year", "file_name", "file_hash"],
            },
            "limitation": (
                "This is a non-oracle source router because it does not consume explicit source labels, but it is still a metadata-schema router. "
                "It should be treated as a routing sanity check, not a deployment-grade semantic source classifier."
            ),
        },
        "routing_metrics": route_metrics,
        "systems": [single, oracle, automatic],
        "automatic_minus_single": {
            "balanced_accuracy": round(automatic["overall"]["balanced_accuracy"] - single["overall"]["balanced_accuracy"], 4),
            "f1": round(automatic["overall"]["f1"] - single["overall"]["f1"], 4),
            "group_all_correct_rate": round(
                automatic["group_metrics"]["group_all_correct_rate"] - single["group_metrics"]["group_all_correct_rate"], 4
            ),
            "orientation_accuracy": round(
                automatic["group_metrics"]["orientation_accuracy"] - single["group_metrics"]["orientation_accuracy"], 4
            ),
        },
        "automatic_minus_oracle": {
            "balanced_accuracy": round(automatic["overall"]["balanced_accuracy"] - oracle["overall"]["balanced_accuracy"], 4),
            "f1": round(automatic["overall"]["f1"] - oracle["overall"]["f1"], 4),
            "group_all_correct_rate": round(
                automatic["group_metrics"]["group_all_correct_rate"] - oracle["group_metrics"]["group_all_correct_rate"], 4
            ),
            "orientation_accuracy": round(
                automatic["group_metrics"]["orientation_accuracy"] - oracle["group_metrics"]["orientation_accuracy"], 4
            ),
        },
        "conclusion": (
            f"{routing_note} The result supports source-aware routing as a system layer, but the next step is a content-based router "
            "that avoids dataset-schema fingerprints."
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Non-Oracle Source Router",
        "",
        "This report replaces explicit source-label routing with a lightweight metadata-schema router.",
        "",
        "## Router Protocol",
        "",
        f"- Forbidden fields: `{', '.join(payload['protocol']['forbidden_fields'])}`",
        f"- Limitation: {payload['protocol']['limitation']}",
        "",
        "## Routing Accuracy",
        "",
        f"- Row accuracy: `{payload['routing_metrics']['row_accuracy']}`",
        f"- Pair-group accuracy: `{payload['routing_metrics']['pair_group_accuracy']}`",
        "",
        "| True Source | Rows | Correct | Accuracy |",
        "| --- | ---: | ---: | ---: |",
    ]
    for source, metrics in payload["routing_metrics"]["by_source"].items():
        lines.append(f"| `{source}` | `{metrics['rows']}` | `{metrics['correct']}` | `{metrics['accuracy']}` |")
    lines.extend(
        [
            "",
            "## System Results",
            "",
            "| System | BA | Recall | Specificity | F1 | Group All-Correct | Orientation |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for system in payload["systems"]:
        overall = system["overall"]
        group = system["group_metrics"]
        lines.append(
            f"| `{system['system']}` | `{overall['balanced_accuracy']}` | `{overall['vulnerable_recall']}` | "
            f"`{overall['safe_specificity']}` | `{overall['f1']}` | `{group['group_all_correct_rate']}` | "
            f"`{group['orientation_accuracy']}` |"
        )
    delta = payload["automatic_minus_single"]
    oracle_delta = payload["automatic_minus_oracle"]
    lines.extend(
        [
            "",
            "## Deltas",
            "",
            f"- Automatic minus single BA: `{delta['balanced_accuracy']}`",
            f"- Automatic minus single group all-correct: `{delta['group_all_correct_rate']}`",
            f"- Automatic minus oracle BA: `{oracle_delta['balanced_accuracy']}`",
            f"- Automatic minus oracle group all-correct: `{oracle_delta['group_all_correct_rate']}`",
            "",
            "## Interpretation",
            "",
            payload["conclusion"],
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a non-oracle source-router report.")
    parser.add_argument("--prime-metadata", default="data/processed/secure_code_primevul_pair_diff_time_eval_ge2021_balanced_2000_metadata.jsonl")
    parser.add_argument("--delta-metadata", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata.jsonl")
    parser.add_argument("--patch-metadata", default="data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl")
    parser.add_argument("--matched-prime-report", default="reports/secure_code_primevul_time_disjoint_matched_mixed_primevul_short_delta_v1.json")
    parser.add_argument("--matched-delta-report", default="reports/secure_code_deltasecommits_matched_mixed_primevul_time_short_delta_pair_diff_eval_v1.json")
    parser.add_argument("--matched-patch-report", default="reports/secure_code_patcheval_zero_shot_matched_mixed_primevul_short_delta_v1.json")
    parser.add_argument("--expert-prime-report", default="reports/secure_code_primevul_time_disjoint_direct_train_v1.json")
    parser.add_argument("--expert-delta-report", default="reports/secure_code_deltasecommits_delta_only_pair_diff_eval_v1.json")
    parser.add_argument("--expert-patch-report", default="reports/secure_code_patcheval_adapter_pair_diff_eval_v1.json")
    parser.add_argument("--json-output", default="reports/secure_code_non_oracle_source_router_v1.json")
    parser.add_argument("--md-output", default="reports/NON_ORACLE_SOURCE_ROUTER.md")
    args = parser.parse_args()

    payload = build_report(
        prime_metadata=read_jsonl(args.prime_metadata),
        delta_metadata=read_jsonl(args.delta_metadata),
        patch_metadata=read_jsonl(args.patch_metadata),
        matched_prime_report=read_json(args.matched_prime_report),
        matched_delta_report=read_json(args.matched_delta_report),
        matched_patch_report=read_json(args.matched_patch_report),
        expert_prime_report=read_json(args.expert_prime_report),
        expert_delta_report=read_json(args.expert_delta_report),
        expert_patch_report=read_json(args.expert_patch_report),
    )
    (ROOT / args.json_output).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (ROOT / args.md_output).write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

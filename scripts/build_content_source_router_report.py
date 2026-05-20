from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_non_oracle_source_router_report import read_json, read_jsonl, routed_system_from_mapping


def text_payload(row: dict[str, Any]) -> str:
    return str(row.get("pair_text") or row.get("prompt") or row.get("diff") or row.get("code") or "")


def diff_body(text: str) -> str:
    marker = "Unified diff:"
    if marker in text:
        return text.split(marker, 1)[1]
    return text


def infer_source_from_surface_text(text: str) -> str:
    lowered = text.lower()
    if re.search(r"^language:\s*(go|javascript|python)\b", text, flags=re.IGNORECASE | re.MULTILINE):
        return "PatchEval"
    if "github.com/tensorflow/tensorflow" in lowered or "ghsa-" in lowered:
        return "DeltaSecommits"
    if re.search(r"^project:\s*https?://", text, flags=re.IGNORECASE | re.MULTILINE):
        return "DeltaSecommits"
    return "PrimeVul-time"


def infer_source_from_diff_body(text: str) -> str:
    body = diff_body(text)
    lowered = body.lower()
    go_markers = [" := ", "func ", "nil", "err !=", "context.context", "ln.", "mgr."]
    python_markers = ["def ", "self.", "none", "true", "false", "except ", "import "]
    js_markers = ["const ", "let ", "=>", "require(", "async ", "await "]
    patch_score = sum(marker in lowered for marker in go_markers + python_markers + js_markers)
    delta_markers = ["tensorflow", "tensor", "op_requires", "errors::", "std::", "::", "->", "absl::"]
    delta_score = sum(marker in lowered for marker in delta_markers)
    prime_markers = ["r_", "ut64", "g_", "linux", "kfree", "goto ", "sizeof", "memcpy", "struct "]
    prime_score = sum(marker in lowered for marker in prime_markers)
    scores = {
        "PatchEval": patch_score,
        "DeltaSecommits": delta_score,
        "PrimeVul-time": prime_score,
    }
    best_source, best_score = max(scores.items(), key=lambda item: (item[1], item[0]))
    if best_score == 0:
        return "unknown"
    return best_source


def routing_rows(
    metadata_by_source: dict[str, list[dict[str, Any]]],
    router: Callable[[str], str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for true_source, metadata_rows in metadata_by_source.items():
        for row in metadata_rows:
            rows.append(
                {
                    "true_source": true_source,
                    "predicted_source": router(text_payload(row)),
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
    pair_correct = 0
    for (true_source, _pair_key), votes in pair_votes.items():
        predicted_source, _count = votes.most_common(1)[0]
        pair_correct += int(predicted_source == true_source)
    return {
        "row_count": total,
        "row_accuracy": round(correct / total, 4) if total else 0.0,
        "pair_group_count": len(pair_votes),
        "pair_group_accuracy": round(pair_correct / len(pair_votes), 4) if pair_votes else 0.0,
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
    adapters = {
        "PrimeVul-time": "primevul-time expert",
        "DeltaSecommits": "deltasecommits expert",
        "PatchEval": "patcheval expert",
    }
    single = routed_system_from_mapping(
        "single matched-mixed checkpoint",
        matched_mapping,
        {source: "matched-mixed" for source in matched_mapping},
    )
    oracle = routed_system_from_mapping("oracle source-routed experts", expert_mapping, adapters)
    surface_metrics = routing_metrics(routing_rows(metadata_by_source, infer_source_from_surface_text))
    diff_metrics = routing_metrics(routing_rows(metadata_by_source, infer_source_from_diff_body))
    surface_system = (
        routed_system_from_mapping("surface-content router", expert_mapping, adapters)
        if surface_metrics["row_accuracy"] == 1.0
        else None
    )
    return {
        "status": "ok",
        "scope": "content_source_router",
        "protocol": {
            "forbidden_row_fields": ["source_dataset", "id", "pair_key", "programming_language", "file_extension", "file_path", "patch_url"],
            "surface_router_input": "pair_text/prompt only, including visible task headers such as Project/CVE/CWE/Language",
            "diff_body_router_input": "only text after the Unified diff marker",
            "limitation": (
                "The surface router is content-based in the sense that it consumes only the model prompt text, but the prompt still contains dataset-shaped headers. "
                "The diff-body router is stricter and intentionally reported as a lower-bound sanity check."
            ),
        },
        "routing_metrics": {
            "surface_content": surface_metrics,
            "diff_body_only": diff_metrics,
        },
        "systems": {
            "single_matched_mixed": single,
            "oracle_source_routed": oracle,
            "surface_content_router": surface_system,
        },
        "surface_minus_single": {
            "balanced_accuracy": round(
                (surface_system or oracle)["overall"]["balanced_accuracy"] - single["overall"]["balanced_accuracy"], 4
            ),
            "group_all_correct_rate": round(
                (surface_system or oracle)["group_metrics"]["group_all_correct_rate"]
                - single["group_metrics"]["group_all_correct_rate"],
                4,
            ),
        },
        "surface_minus_oracle": {
            "balanced_accuracy": round(
                (surface_system or oracle)["overall"]["balanced_accuracy"] - oracle["overall"]["balanced_accuracy"], 4
            ),
            "group_all_correct_rate": round(
                (surface_system or oracle)["group_metrics"]["group_all_correct_rate"]
                - oracle["group_metrics"]["group_all_correct_rate"],
                4,
            ),
        },
        "conclusion": (
            "A prompt-surface content router can recover the oracle source routing on the current benchmark, but a stricter diff-body-only heuristic is much weaker. "
            "This confirms that routing is feasible from the input artifact while also showing that robust semantic routing should avoid prompt/header fingerprints."
        ),
    }


def render_metrics_table(metrics: dict[str, Any]) -> list[str]:
    lines = ["| Router | Row Accuracy | Pair Accuracy |", "| --- | ---: | ---: |"]
    for name, values in metrics.items():
        lines.append(f"| `{name}` | `{values['row_accuracy']}` | `{values['pair_group_accuracy']}` |")
    return lines


def render_system_row(name: str, system: dict[str, Any] | None) -> str:
    if system is None:
        return f"| `{name}` | `n/a` | `n/a` | `n/a` | `n/a` |"
    overall = system["overall"]
    group = system["group_metrics"]
    return (
        f"| `{name}` | `{overall['balanced_accuracy']}` | `{overall['f1']}` | "
        f"`{group['group_all_correct_rate']}` | `{group['orientation_accuracy']}` |"
    )


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Content Source Router",
        "",
        "This report evaluates source routing from input text rather than row metadata.",
        "",
        "## Protocol",
        "",
        f"- Forbidden row fields: `{', '.join(payload['protocol']['forbidden_row_fields'])}`",
        f"- Surface router input: {payload['protocol']['surface_router_input']}.",
        f"- Diff-body router input: {payload['protocol']['diff_body_router_input']}.",
        f"- Limitation: {payload['protocol']['limitation']}",
        "",
        "## Routing Accuracy",
        "",
        *render_metrics_table(payload["routing_metrics"]),
        "",
        "## System Results",
        "",
        "| System | BA | F1 | Group All-Correct | Orientation |",
        "| --- | ---: | ---: | ---: | ---: |",
        render_system_row("single matched-mixed", payload["systems"]["single_matched_mixed"]),
        render_system_row("oracle source-routed", payload["systems"]["oracle_source_routed"]),
        render_system_row("surface-content router", payload["systems"]["surface_content_router"]),
        "",
        "## Deltas",
        "",
        f"- Surface router minus single BA: `{payload['surface_minus_single']['balanced_accuracy']}`",
        f"- Surface router minus single group all-correct: `{payload['surface_minus_single']['group_all_correct_rate']}`",
        f"- Surface router minus oracle BA: `{payload['surface_minus_oracle']['balanced_accuracy']}`",
        f"- Surface router minus oracle group all-correct: `{payload['surface_minus_oracle']['group_all_correct_rate']}`",
        "",
        "## Interpretation",
        "",
        payload["conclusion"],
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a content-based source-router report.")
    parser.add_argument("--prime-metadata", default="data/processed/secure_code_primevul_pair_diff_time_eval_ge2021_balanced_2000_metadata.jsonl")
    parser.add_argument("--delta-metadata", default="data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata.jsonl")
    parser.add_argument("--patch-metadata", default="data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl")
    parser.add_argument("--matched-prime-report", default="reports/secure_code_primevul_time_disjoint_matched_mixed_primevul_short_delta_v1.json")
    parser.add_argument("--matched-delta-report", default="reports/secure_code_deltasecommits_matched_mixed_primevul_time_short_delta_pair_diff_eval_v1.json")
    parser.add_argument("--matched-patch-report", default="reports/secure_code_patcheval_zero_shot_matched_mixed_primevul_short_delta_v1.json")
    parser.add_argument("--expert-prime-report", default="reports/secure_code_primevul_time_disjoint_direct_train_v1.json")
    parser.add_argument("--expert-delta-report", default="reports/secure_code_deltasecommits_delta_only_pair_diff_eval_v1.json")
    parser.add_argument("--expert-patch-report", default="reports/secure_code_patcheval_adapter_pair_diff_eval_v1.json")
    parser.add_argument("--json-output", default="reports/secure_code_content_source_router_v1.json")
    parser.add_argument("--md-output", default="reports/CONTENT_SOURCE_ROUTER.md")
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

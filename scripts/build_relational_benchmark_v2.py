from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_json, write_jsonl
from vrf.relational_benchmark import (
    build_canonical_pair,
    build_interventions,
    pair_metadata,
    render_pair,
    sample_pairs,
    token_accounting,
)


DEFAULT_SOURCES = [
    "primevul=data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl",
    "deltasecommits=data/processed/secure_code_deltasecommits_pair_diff_cpp_eval_metadata.jsonl",
    "patcheval=data/processed/secure_code_patcheval_pair_diff_eval_metadata.jsonl",
]


def parse_source(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise ValueError("source must use name=path")
    name, path = value.split("=", 1)
    return name.strip(), ROOT / path.strip()


def load_pairs(name: str, path: Path):
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in read_jsonl(path):
        grouped.setdefault(str(row.get("pair_key") or row["id"]), []).append(row)
    pairs = []
    skipped = 0
    for pair_key, rows in grouped.items():
        try:
            pairs.append(build_canonical_pair(pair_key, rows, dataset=name))
        except ValueError:
            skipped += 1
    return pairs, skipped


def tokenizer_encoder(checkpoint: str):
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(checkpoint, local_files_only=True)

    class Encoder:
        def __call__(self, text: str) -> list[int]:
            return tokenizer.encode(text, add_special_tokens=False)

        @staticmethod
        def truncate_text(text: str, max_length: int) -> str:
            token_ids = tokenizer.encode(text, add_special_tokens=False)
            return tokenizer.decode(token_ids[:max_length], skip_special_tokens=True)

    return Encoder()


def build_rows(pairs, *, encode, max_length: int, seed: int) -> list[dict[str, Any]]:
    rows = []
    for pair in pairs:
        metadata = pair_metadata(pair, encode=encode)
        base_id = f"{pair.dataset}::{pair.pair_key}::base"
        base_text = render_pair(pair)
        rows.append(
            {
                "id": base_id,
                "base_id": base_id,
                **metadata,
                "transformation_family": "base",
                "transformation_template": "canonical_pair_renderer_v1",
                "expected_relation": "identity",
                "validation_tier": 1,
                "validation": {
                    "structural_valid": True,
                    "semantic_basis": "canonical vulnerable/fixed pair",
                },
                "changed_regions": [],
                "text": base_text,
                "token_accounting": token_accounting(
                    base_text,
                    base_text,
                    encode=encode,
                    max_length=max_length,
                ),
                "generator_version": "relational_benchmark_v2",
                "seed": seed,
            }
        )
        for intervention in build_interventions(pair, encode=encode, max_length=max_length):
            transformed_gold = metadata["gold_riskier_side"]
            if intervention.expected_relation == "equivariant_swap":
                transformed_gold = "B" if transformed_gold == "A" else "A"
            rows.append(
                {
                    "id": f"{base_id}::{intervention.template}",
                    "base_id": base_id,
                    **metadata,
                    "base_gold_riskier_side": metadata["gold_riskier_side"],
                    "gold_riskier_side": transformed_gold,
                    "transformation_family": intervention.family,
                    "transformation_template": intervention.template,
                    "expected_relation": intervention.expected_relation,
                    "validation_tier": intervention.validation_tier,
                    "validation": intervention.validation,
                    "changed_regions": intervention.changed_regions,
                    "text": intervention.text,
                    "token_accounting": intervention.token_accounting,
                    "generator_version": "relational_benchmark_v2",
                    "seed": seed,
                }
            )
    return rows


def summarize(rows: list[dict[str, Any]], source_summaries: dict[str, Any], args) -> dict[str, Any]:
    base_rows = [row for row in rows if row["transformation_family"] == "base"]
    intervention_rows = [row for row in rows if row["transformation_family"] != "base"]
    no_truncation = [
        row
        for row in intervention_rows
        if not row["token_accounting"].get("critical_hunk_truncated")
    ]
    introduced_truncation = [
        row
        for row in intervention_rows
        if row["token_accounting"].get("transformation_introduced_critical_truncation")
    ]
    truncation_by_template = {}
    for template in sorted({row["transformation_template"] for row in intervention_rows}):
        template_rows = [row for row in intervention_rows if row["transformation_template"] == template]
        truncation_by_template[template] = {
            "rows": len(template_rows),
            "base_critical_hunk_truncated": sum(
                bool(row["token_accounting"].get("base_critical_hunk_truncated"))
                for row in template_rows
            ),
            "transformation_introduced_critical_truncation": sum(
                bool(row["token_accounting"].get("transformation_introduced_critical_truncation"))
                for row in template_rows
            ),
            "no_critical_hunk_truncation": sum(
                not bool(row["token_accounting"].get("critical_hunk_truncated"))
                for row in template_rows
            ),
        }
    return {
        "status": "ok",
        "benchmark": "pairwise_secure_patch_orientation_v2",
        "pairs": len(base_rows),
        "rows": len(rows),
        "intervention_rows": len(intervention_rows),
        "sampling": {
            "mode": args.sampling,
            "seed": args.seed,
            "max_pairs_per_source": args.max_pairs_per_source,
            "stratify_by": args.stratify_by.split(","),
        },
        "tokenizer": args.tokenizer,
        "max_length": args.max_length,
        "source_summaries": source_summaries,
        "datasets": dict(Counter(row["dataset"] for row in base_rows)),
        "languages": dict(Counter(row["language"] for row in base_rows)),
        "diff_buckets": dict(Counter(row["diff_bucket"] for row in base_rows)),
        "token_buckets": dict(Counter(row["token_bucket"] for row in base_rows)),
        "transformation_templates": dict(
            Counter(row["transformation_template"] for row in intervention_rows)
        ),
        "validation_tiers": dict(Counter(str(row["validation_tier"]) for row in intervention_rows)),
        "no_critical_hunk_truncation_rows": len(no_truncation),
        "critical_hunk_truncation_rows": len(intervention_rows) - len(no_truncation),
        "transformation_introduced_critical_truncation_rows": len(introduced_truncation),
        "truncation_by_template": truncation_by_template,
        "claim_boundary": (
            "V2 includes prompt-level metadata, padding/context-pressure, and canonical side-order "
            "transformations. Regex identifier renaming and generic formatting are excluded from the "
            "validated set until parser-aware implementations exist."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the semantics-auditable relational benchmark v2.")
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--sampling", choices=["representative", "balanced", "stress"], default="balanced")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-pairs-per-source", type=int, default=200)
    parser.add_argument(
        "--stratify-by",
        default="language,cwe,diff_bucket,token_bucket,project,year",
    )
    parser.add_argument(
        "--tokenizer",
        default="checkpoints/cls_secure_code_primevul_joint_pairwise_qwen15b_lora_v1",
    )
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_relational_benchmark_v2.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_relational_benchmark_v2_summary.json",
    )
    args = parser.parse_args()

    encode = tokenizer_encoder(args.tokenizer)
    all_rows = []
    source_summaries = {}
    for source_value in args.source or DEFAULT_SOURCES:
        name, path = parse_source(source_value)
        pairs, skipped = load_pairs(name, path)
        selected = sample_pairs(
            pairs,
            limit=args.max_pairs_per_source,
            seed=args.seed,
            mode=args.sampling,
            encode=encode,
            stratify_by=[part.strip() for part in args.stratify_by.split(",") if part.strip()],
        )
        all_rows.extend(build_rows(selected, encode=encode, max_length=args.max_length, seed=args.seed))
        source_summaries[name] = {
            "input": str(path.relative_to(ROOT)).replace("\\", "/"),
            "eligible_pairs": len(pairs),
            "selected_pairs": len(selected),
            "skipped_groups": skipped,
        }
    write_jsonl(ROOT / args.output, all_rows)
    summary = summarize(all_rows, source_summaries, args)
    write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

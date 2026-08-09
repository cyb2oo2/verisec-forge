"""Build the held-out nuisance-transform transfer audit (repair evaluation only).

Regenerates the exact same 600 PrimeVul/DeltaSecommits/PatchEval canonical
pairs used by the polarity-only-swap audit (same default sources, same
`sample_representative(limit=200, seed=42)` per source -- verified to produce
identical `pair_key`s to `data/processed/secure_code_relational_benchmark_v2.jsonl`),
then renders each of the five held-out nuisance families
(`src/vrf/nuisance_transfer.py`) as a canonical + side-swap audit row pair. No
model is run and no training happens here -- this is evaluation-dataset
construction only, per `docs/REPAIR_EXPERIMENT_PREREGISTRATION.md`'s
still-unrun nuisance-transform transfer leg.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (SRC, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from vrf.io_utils import write_json, write_jsonl
from vrf.qwen_mechanism_audit import audit_row
from vrf.relational_benchmark import pair_metadata, sample_representative
from vrf.nuisance_transfer import NUISANCE_FAMILIES, build_nuisance_rows

from scripts.build_relational_benchmark_v2 import DEFAULT_SOURCES, load_pairs, parse_source


def build_base_pairs(*, limit: int, seed: int, sources: list[str] | None = None):
    all_pairs = []
    per_source = {}
    for source_value in sources or DEFAULT_SOURCES:
        name, path = parse_source(source_value)
        pairs, skipped, rejected_non_mirror = load_pairs(name, path)
        representative = sample_representative(pairs, limit=limit, seed=seed)
        per_source[name] = {
            "eligible_pairs": len(pairs),
            "skipped_groups": skipped,
            "rejected_non_mirror_pairs": rejected_non_mirror,
            "sampled": len(representative),
        }
        all_pairs.extend(representative)
    return all_pairs, per_source


def variant_name(family: str, side: str) -> str:
    return f"{side}__{family}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=200, help="pairs per source (matches the original 600-pair audit: 3 sources x 200)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--source",
        action="append",
        help="name=path; repeatable. Defaults to the three primary sources.",
    )
    parser.add_argument(
        "--output",
        default="data/processed/secure_code_nuisance_transfer_audit_v1.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        default="reports/secure_code_nuisance_transfer_audit_dataset_v1.json",
    )
    args = parser.parse_args()

    base_pairs, per_source = build_base_pairs(
        limit=args.limit, seed=args.seed, sources=args.source
    )

    rows: list[dict[str, Any]] = []
    build_errors: list[dict[str, str]] = []
    for pair in base_pairs:
        base = pair_metadata(pair)
        for family in NUISANCE_FAMILIES:
            try:
                canonical_text, side_swap_text = build_nuisance_rows(pair, family)
            except Exception as exc:  # pragma: no cover - defensive, reported not raised
                build_errors.append(
                    {"pair_key": base["pair_key"], "family": family, "error": str(exc)}
                )
                continue
            rows.append(
                audit_row(
                    base,
                    variant=variant_name(family, "canonical"),
                    family=family,
                    text=canonical_text,
                    expected_relation="identity",
                )
            )
            rows.append(
                audit_row(
                    base,
                    variant=variant_name(family, "side_swap"),
                    family=family,
                    text=side_swap_text,
                    expected_relation="equivariant_swap",
                    gold_side="B" if base["gold_riskier_side"] == "A" else "A",
                )
            )

    write_jsonl(ROOT / args.output, rows)
    summary = {
        "status": "ok" if not build_errors else "partial",
        "scope": "nuisance_transfer_audit",
        "base_pairs": len(base_pairs),
        "rows": len(rows),
        "nuisance_families": NUISANCE_FAMILIES,
        "variants_per_family": ["canonical", "side_swap"],
        "per_source": per_source,
        "build_errors": build_errors,
        "note": (
            "Not part of the original polarity-only-swap audit's training/"
            "evaluation loop. Reuses the identical 600 base pairs (verified "
            "pair_key match) for direct comparability to the #54 PrimeVul "
            "in-distribution numbers."
        ),
    }
    write_json(ROOT / args.summary_output, summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if not build_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())

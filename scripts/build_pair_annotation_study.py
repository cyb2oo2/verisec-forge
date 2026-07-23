from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.io_utils import read_jsonl, write_jsonl
from vrf.pair_annotation import (
    ANNOTATION_FIELDS,
    DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE,
    DEFAULT_SINGLE_AUTHOR_SEED,
    STUDY_ID_SINGLE_AUTHOR_50,
    build_blinded_packet,
    select_high_value_pairs,
    single_author_claim_boundary,
    single_author_study_id,
)


def changed_lines(pair_text: str) -> int:
    return sum(
        1
        for line in str(pair_text).splitlines()
        if (line.startswith("+") and not line.startswith("+++")) or (line.startswith("-") and not line.startswith("---"))
    )


def build_pair_pool(dataset_rows: list[dict[str, Any]], prediction_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    predictions = {str(row["id"]): row for row in prediction_rows}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in dataset_rows:
        grouped.setdefault(str(row.get("pair_key") or row["id"]), []).append(row)

    pairs: list[dict[str, Any]] = []
    for pair_key, rows in grouped.items():
        if len(rows) != 2:
            continue
        probabilities = [float(predictions.get(str(row["id"]), {}).get("vuln_probability") or 0.0) for row in rows]
        predictions_for_pair = [int(predictions.get(str(row["id"]), {}).get("pred", 0)) for row in rows]
        gold = [int(bool(row.get("has_vulnerability"))) for row in rows]
        vulnerable_rows = [row for row in rows if bool(row.get("has_vulnerability"))]
        pairs.append(
            {
                "pair_key": pair_key,
                "rows": rows,
                "gold_vulnerable_id": vulnerable_rows[0]["id"] if len(vulnerable_rows) == 1 else None,
                "probability_gap": abs(probabilities[0] - probabilities[1]),
                "model_pair_correct": predictions_for_pair == gold,
                "changed_lines": max(changed_lines(row.get("pair_text", "")) for row in rows),
            }
        )
    return pairs


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ANNOTATION_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a stratified blinded pair-annotation study (default: single-author n=50)."
    )
    parser.add_argument(
        "--dataset",
        default="data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl",
    )
    parser.add_argument(
        "--predictions",
        default="outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl",
    )
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE)
    parser.add_argument("--seed", type=int, default=DEFAULT_SINGLE_AUTHOR_SEED)
    parser.add_argument(
        "--mode",
        choices=["single_author", "dual_independent"],
        default="single_author",
        help="single_author (default): one packet + annotator_answers.csv; dual_independent: legacy two-rater setup.",
    )
    parser.add_argument(
        "--allow-nondefault-study-id",
        action="store_true",
        help=(
            "Required when single_author sample-size/seed differ from the canonical "
            f"n={DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE} seed={DEFAULT_SINGLE_AUTHOR_SEED} "
            f"({STUDY_ID_SINGLE_AUTHOR_50}). Prevents accidental mislabeling."
        ),
    )
    parser.add_argument("--output-dir", default="data/annotation/primevul_pair_study_v1")
    parser.add_argument("--summary-output", default="reports/secure_code_primevul_pair_annotation_study_v1.json")
    args = parser.parse_args()

    if args.mode == "single_author":
        is_default = (
            args.sample_size == DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE
            and args.seed == DEFAULT_SINGLE_AUTHOR_SEED
        )
        if not is_default and not args.allow_nondefault_study_id:
            raise SystemExit(
                "single_author non-default sample-size/seed requires "
                "--allow-nondefault-study-id (canonical study is "
                f"n={DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE} seed={DEFAULT_SINGLE_AUTHOR_SEED}, "
                f"id={STUDY_ID_SINGLE_AUTHOR_50}). "
                f"Requested sample-size={args.sample_size} seed={args.seed} would be labeled "
                f"{single_author_study_id(args.sample_size, args.seed)!r}."
            )

    pool = build_pair_pool(read_jsonl(ROOT / args.dataset), read_jsonl(ROOT / args.predictions))
    selected = select_high_value_pairs(pool, sample_size=args.sample_size, seed=args.seed)
    if len(selected) != args.sample_size:
        raise SystemExit(
            f"materialized {len(selected)} pairs but requested {args.sample_size}; check pool size"
        )

    output_dir = ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    mapping_rows: list[dict[str, Any]] = []
    if args.mode == "single_author":
        packet, answers, mappings = build_blinded_packet(
            selected,
            annotator_id="author",
            seed=args.seed + 1,
        )
        write_jsonl(output_dir / "annotator_packet.jsonl", packet)
        # Primary empty template name requested by protocol.
        write_csv(output_dir / "annotator_answers.csv", answers)
        mapping_rows.extend(mappings)
        # Remove legacy dual-annotator artifacts if present so staff do not mix modes.
        for legacy in (
            "annotator_1_packet.jsonl",
            "annotator_1_answers.csv",
            "annotator_2_packet.jsonl",
            "annotator_2_answers.csv",
        ):
            legacy_path = output_dir / legacy
            if legacy_path.exists():
                legacy_path.unlink()
        study_id = single_author_study_id(args.sample_size, args.seed)
        protocol = "single_author_blinded_audit"
        claim = single_author_claim_boundary(args.sample_size)
        publishable = {
            "completed_by_author": args.sample_size,
            "target_completed": len(selected),
            "report_inter_annotator_kappa": False,
            "note": "No dual-rater κ; single-author audit only.",
        }
        files = {
            "packet": "annotator_packet.jsonl",
            "answers": "annotator_answers.csv",
            "mapping": "private_case_mapping.jsonl",
        }
    else:
        for offset, annotator_id in enumerate(["annotator_1", "annotator_2"], start=1):
            packet, answers, mappings = build_blinded_packet(
                selected,
                annotator_id=annotator_id,
                seed=args.seed + offset,
            )
            write_jsonl(output_dir / f"{annotator_id}_packet.jsonl", packet)
            write_csv(output_dir / f"{annotator_id}_answers.csv", answers)
            mapping_rows.extend(mappings)
        study_id = "primevul_pair_study_v1"
        protocol = "two_independent_blinded_annotators"
        claim = {
            "human_gold_not_ai_pilot": True,
            "not_prevalence_estimate": True,
            "annotation_labels_not_filled_by_build": True,
        }
        publishable = {
            "completed_by_both_annotators": min(100, len(selected)),
            "target_completed_by_both_annotators": len(selected),
            "report_side_cohen_kappa": True,
            "report_context_cohen_kappa": True,
            "adjudicate_all_disagreements": True,
        }
        files = {
            "packet_1": "annotator_1_packet.jsonl",
            "packet_2": "annotator_2_packet.jsonl",
            "answers_1": "annotator_1_answers.csv",
            "answers_2": "annotator_2_answers.csv",
            "mapping": "private_case_mapping.jsonl",
        }

    write_jsonl(output_dir / "private_case_mapping.jsonl", mapping_rows)

    strata: dict[str, int] = {}
    for row in selected:
        strata[row["selection_stratum"]] = strata.get(row["selection_stratum"], 0) + 1

    summary = {
        "status": "ok",
        "protocol": protocol,
        "mode": args.mode,
        "study_id": study_id,
        "seed": args.seed,
        "requested_pairs": args.sample_size,
        "materialized_pairs": len(selected),
        "candidate_pairs": len(pool),
        "selection_strata": dict(sorted(strata.items())),
        "output_dir": args.output_dir.replace("\\", "/"),
        "files": files,
        "annotation_fields": ANNOTATION_FIELDS,
        "packet_blinding": {
            "randomized_case_order": True,
            "randomized_side_assignment": True,
            "scrub_project_cve_cwe_from_diff_text": True,
            "scrub_identity_from_code_and_diff": True,
            "exclude_model_scores_from_packet": True,
            "private_mapping_staff_only": True,
        },
        "claim_boundary": claim,
        "minimum_publishable_gate": publishable,
        "tools": {
            "annotator_guide": "docs/PAIR_ANNOTATION_ANNOTATOR_GUIDE.md",
            "status": "scripts/check_pair_annotation_study_status.py",
            "validate": "scripts/validate_pair_annotation_answers.py",
            "export_sheets": "scripts/export_pair_annotation_review_sheets.py",
        },
    }
    summary_path = ROOT / args.summary_output
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

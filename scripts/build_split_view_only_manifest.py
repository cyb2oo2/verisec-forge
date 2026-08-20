"""Build the split-view-only training reproducibility manifest.

Binds `reports/SPLIT_VIEW_ONLY_TRAINING_V1.md` and its JSON to the small input
artifacts that produced them. Checkpoint weights are local and are deliberately
excluded: only the declared checkpoint identity is recorded.

Verify with:

    python scripts/build_reproducibility_bundle.py \
      --manifest reproducibility/split_view_only_training_manifest.json \
      --check-only --include-generated
"""

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
from vrf.split_view_only import (
    AMENDMENT_DATE,
    AMENDMENT_ID,
    ANALYSIS_CODE,
    PREDECLARED_OUTPUT_DIR,
)

CONFIG = "configs/research_split_view_only_qwen3b_v1.json"
REPORT_JSON = "reports/veripatch_rr_split_view_only_training.json"
REPORT_MD = "reports/SPLIT_VIEW_ONLY_TRAINING_V1.md"
PROTOCOL = "docs/SPLIT_VIEW_ONLY_TRAINING_PROTOCOL.md"
TRAIN_STATUS = "reports/repair_train_status_split_view_only_qwen3b_v1.json"
SUITE = "data/processed/secure_code_relational_benchmark_v4_runtime1024.jsonl"
SUITE_SUMMARY = "reports/secure_code_relational_benchmark_v4_summary.json"
PREDICTIONS = "outputs/secure_code_v4_split_view_only_qwen3b_predictions_1024.jsonl"


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
    report = read_json(ROOT / REPORT_JSON)
    verdict = report["verdict"]
    repro = report.get("reproducibility") or {}

    artifacts = [
        entry("config", CONFIG),
        entry("train_status", TRAIN_STATUS),
        entry("protocol", PROTOCOL),
        entry("eval_suite", SUITE),
        entry("eval_suite_summary", SUITE_SUMMARY),
        entry("predictions", PREDICTIONS),
    ]
    # The code that produced the adjudication is bound directly, so
    # --check-only detects an edited analyser. Nested code hashes inside the
    # report JSON are not seen by the generic manifest verifier.
    artifacts.extend(entry(role, path) for role, path in ANALYSIS_CODE)

    generated = [
        entry("report_json", REPORT_JSON),
        entry("report_markdown", REPORT_MD),
    ]

    return {
        "name": "split_view_only_training_v1",
        "description": (
            "Arc 2 Q1 split-view-only training adjudication: one from-scratch "
            "3B run on split_view only, evaluated on the admissible v4 suite."
        ),
        # No created_utc: this manifest is deterministic, and the amendment
        # date is protocol history, not a manifest creation time.
        "amendment_date": AMENDMENT_DATE,
        "amendment": {
            "id": AMENDMENT_ID,
            "date": AMENDMENT_DATE,
            "status": "post-run",
            "document": PROTOCOL,
        },
        "analysis_command": [
            "python",
            "scripts/analyze_split_view_only_training.py",
        ],
        "validation_command": [
            "python",
            "scripts/build_reproducibility_bundle.py",
            "--manifest",
            "reproducibility/split_view_only_training_manifest.json",
            "--check-only",
            "--include-generated",
        ],
        "artifacts": artifacts,
        "generated_artifacts": generated,
        "expected": {
            "primary_outcome": verdict["primary_outcome"],
            "stop_training": verdict["stop_training"],
            "provenance_ok": verdict["provenance_ok"],
            "prediction_provenance_ok": verdict["prediction_provenance_ok"],
            "degeneracy_delta_threshold": verdict["degeneracy_delta_threshold"],
        },
        "checkpoint_identity": {
            "checkpoint": PREDECLARED_OUTPUT_DIR,
            "model_name": report.get("resolved_config", {}).get("model_name"),
            "note": (
                "Checkpoint weights are local, are not committed, and are not "
                "hashed by this manifest. Only the declared identity is bound."
            ),
        },
        "source_commit": repro.get("git_commit"),
        "source_commit_note": (
            "The commit HEAD pointed at when the report was generated. It does "
            "not necessarily contain the analysis code — see "
            "publication_blockers.stale_source_commit."
        ),
        "git_working_tree_dirty": repro.get("git_working_tree_dirty"),
        "local_analysis_reproducible": bool(repro.get("local_analysis_reproducible")),
        "publication_ready": bool(repro.get("publication_ready")),
        "publication_blockers": repro.get("publication_blockers"),
        "publication_blocking_reasons": repro.get("publication_blocking_reasons"),
        "limitations": [
            "The manifest reproduces analysis from stored predictions, not GPU "
            "training. No model is retrained by the validation command.",
            "Model checkpoints are local and are not included in Git or this "
            "manifest; only the declared checkpoint identity is bound. Their "
            "weights are unverified.",
            "A passing --check-only proves the local files match their hashes. "
            "It does not make this artifact fresh-clone reproducible: "
            "local_analysis_reproducible and publication_ready are separate "
            "properties and only the first can be established locally.",
            "ceiling_holds is an adjudication label, not proof that all "
            "relational information is absent.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default="reproducibility/split_view_only_training_manifest.json",
    )
    args = parser.parse_args()
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = build_manifest()
    output.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": "ok",
                "output": args.output,
                "artifact_count": len(manifest["artifacts"]),
                "generated_count": len(manifest["generated_artifacts"]),
                "publication_ready": manifest["publication_ready"],
                "publication_blockers": manifest["publication_blockers"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

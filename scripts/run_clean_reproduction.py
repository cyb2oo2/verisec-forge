"""Single documented clean-run path with a machine-readable provenance manifest.

This is the entrypoint a reviewer should use. It:

* records the environment (commit, Python, dependency versions);
* optionally fetches published artifact bundles and verifies their hashes;
* runs every currently *supported* result builder in order;
* fails loudly, with a non-zero exit, when a required artifact is missing;
* hashes every input and output;
* writes a provenance manifest recording, per stage, whether the result was
  **computed** in this run or **copied** from a historical artifact.

Stages whose inputs are absent are reported as ``blocked`` with the exact
remediation command. They are never silently skipped and never filled in with
remembered numbers.

Usage::

    python scripts/run_clean_reproduction.py --fetch          # download bundles first
    python scripts/run_clean_reproduction.py                  # use local artifacts
    python scripts/run_clean_reproduction.py --allow-blocked  # report, don't exit non-zero
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

PYTHON = sys.executable

CALIBRATED = "reports/secure_code_primevul_directional_bucket_router_calibrated_v1_report.json"
EVAL_DATASET = "data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl"
TRAIN_DATASET = "data/processed/secure_code_primevul_pair_diff_only_train_balanced_3000_metadata.jsonl"
MAINLINE_PREDICTIONS = (
    "outputs/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_3000_v1_eval1792_dedup_predictions.jsonl"
)
BUNDLE_HINT = (
    "python scripts/download_reproducibility_bundle.py "
    "--bundle-name primevul_router_and_evidence_coupled_inputs --restore"
)

# Every stage declares its inputs so a missing artifact is reported before the
# subprocess runs, with a remediation command rather than a stack trace.
STAGES: list[dict[str, Any]] = [
    {
        "name": "audit_verification",
        "description": "Reproduce the independent audit findings against this tree.",
        "command": [PYTHON, "scripts/verify_audit_findings.py"],
        "inputs": [],
        "outputs": [
            "reports/RESEARCH_INTEGRITY_VERIFICATION.json",
            "docs/RESEARCH_INTEGRITY_VERIFICATION.md",
        ],
        "seeds": {"tie_break": 0},
    },
    {
        "name": "polarity_structural_control",
        "description": "Semantics-free diff-shape control for the paired-diff mainline.",
        "command": [PYTHON, "scripts/evaluate_polarity_structural_control.py"],
        "inputs": [TRAIN_DATASET, EVAL_DATASET, MAINLINE_PREDICTIONS],
        "outputs": [
            "reports/secure_code_primevul_polarity_structural_control_v1.json",
            "reports/PRIMEVUL_POLARITY_STRUCTURAL_CONTROL.md",
        ],
        "seeds": {"tie_break": 20260727},
    },
    {
        "name": "pair_coupled_constraint_decomposition",
        "description": "Isolate the closed-world constraint from the model.",
        "command": [PYTHON, "scripts/evaluate_pair_coupled_constraint_decomposition.py"],
        "inputs": [CALIBRATED, TRAIN_DATASET, EVAL_DATASET],
        "outputs": [
            "reports/secure_code_primevul_pair_coupled_constraint_decomposition_v1.json",
            "reports/PRIMEVUL_PAIR_COUPLED_CONSTRAINT_DECOMPOSITION.md",
        ],
        "seeds": {"bootstrap": 20260727},
    },
    {
        "name": "pair_coupled_clustered_statistics",
        "description": "Pair-group clustered inference replacing the overlapping-split bootstrap.",
        "command": [PYTHON, "scripts/build_primevul_pair_coupled_clustered_statistics.py"],
        "inputs": [CALIBRATED, EVAL_DATASET],
        "outputs": [
            "reports/secure_code_primevul_pair_coupled_clustered_statistics_v1.json",
            "reports/PRIMEVUL_PAIR_COUPLED_CLUSTERED_STATISTICS.md",
        ],
        "seeds": {"bootstrap": 20260727},
    },
    {
        "name": "evidence_heuristic_consistency",
        "description": "Evidence analysis with the circular target removed.",
        "command": [PYTHON, "scripts/evaluate_evidence_heuristic_consistency.py"],
        "inputs": [],
        "outputs": [
            "reports/secure_code_primevul_evidence_heuristic_consistency_v1.json",
            "reports/PRIMEVUL_EVIDENCE_HEURISTIC_CONSISTENCY.md",
        ],
        "seeds": {},
    },
    {
        "name": "gate_uncertainty",
        "description": "Safe-flip gate precision with exact intervals and selection provenance.",
        "command": [PYTHON, "scripts/build_primevul_side_inversion_gate_uncertainty.py"],
        "inputs": [],
        "outputs": [
            "reports/secure_code_primevul_side_inversion_gate_uncertainty_v1.json",
            "reports/PRIMEVUL_SIDE_INVERSION_GATE_UNCERTAINTY.md",
        ],
        "seeds": {},
    },
]

# Result files that exist in the tree but cannot be regenerated from it.
HISTORICAL_ONLY = {
    "reports/PRIMEVUL_MAIN_RESULTS.md": "requires reports/*_threshold_sweep.json (absent)",
    "paper/tables/main_results.md": "requires reports/*_threshold_sweep.json (absent)",
    "reports/PRIMEVUL_PAIR_COUPLED_SIGNIFICANCE.md": "withdrawn; superseded by clustered statistics",
    "reports/PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md": "withdrawn; circular target",
}


def sha256(path: Path) -> str | None:
    if not path.exists() or path.is_dir():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str]) -> tuple[int, str]:
    completed = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True)
    return completed.returncode, (completed.stdout or "") + (completed.stderr or "")


def environment() -> dict[str, Any]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True
        ).stdout.strip()
    )
    freeze = subprocess.run(
        [PYTHON, "-m", "pip", "freeze", "--disable-pip-version-check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    return {
        "git_commit": commit or "unknown",
        "git_working_tree_dirty": dirty,
        "python_version": sys.version.split()[0],
        "python_executable": PYTHON,
        "platform": platform.platform(),
        "dependency_versions": sorted(line for line in freeze if line and not line.startswith("-e ")),
    }


def fetch_bundles(bundles: list[str]) -> list[dict[str, Any]]:
    results = []
    for bundle in bundles:
        code, output = run(
            [
                PYTHON,
                "scripts/download_reproducibility_bundle.py",
                "--bundle-name",
                bundle,
                "--restore",
            ]
        )
        results.append(
            {
                "bundle": bundle,
                "exit_code": code,
                "hash_verified": code == 0,
                "output_tail": output.strip().splitlines()[-5:],
            }
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Clean-run reproduction with provenance manifest.")
    parser.add_argument("--fetch", action="store_true", help="download and verify published bundles first")
    parser.add_argument(
        "--bundle",
        action="append",
        default=None,
        help="bundle name to fetch (repeatable); defaults to the PrimeVul router bundle",
    )
    parser.add_argument(
        "--allow-blocked",
        action="store_true",
        help="report blocked stages without exiting non-zero (still never fabricates results)",
    )
    parser.add_argument("--manifest", default="reports/REPRODUCTION_PROVENANCE.json")
    args = parser.parse_args()

    started = datetime.now(timezone.utc).isoformat()
    manifest: dict[str, Any] = {
        "scope": "verisec_forge_clean_reproduction",
        "started_at_utc": started,
        "environment": environment(),
        "bundles": [],
        "stages": [],
        "historical_only_outputs": [
            {"path": path, "status": "historical_not_regenerable", "reason": reason}
            for path, reason in sorted(HISTORICAL_ONLY.items())
        ],
    }

    if args.fetch:
        manifest["bundles"] = fetch_bundles(args.bundle or ["primevul_router_and_evidence_coupled_inputs"])

    blocked = 0
    failed = 0
    for stage in STAGES:
        missing = [path for path in stage["inputs"] if not (REPO_ROOT / path).exists()]
        record: dict[str, Any] = {
            "name": stage["name"],
            "description": stage["description"],
            "command": " ".join(stage["command"]),
            "seeds": stage["seeds"],
            "inputs": [
                {"path": path, "sha256": sha256(REPO_ROOT / path), "present": (REPO_ROOT / path).exists()}
                for path in stage["inputs"]
            ],
        }
        if missing:
            blocked += 1
            record.update(
                {
                    "status": "blocked",
                    "result_origin": "not_produced",
                    "missing_inputs": missing,
                    "remediation": BUNDLE_HINT,
                }
            )
            print(f"[blocked] {stage['name']}: missing {missing[0]}")
        else:
            code, output = run(stage["command"])
            record.update(
                {
                    "status": "computed" if code == 0 else "failed",
                    "result_origin": "computed_in_this_run" if code == 0 else "not_produced",
                    "exit_code": code,
                    "output_tail": output.strip().splitlines()[-8:],
                }
            )
            if code != 0:
                failed += 1
                print(f"[FAILED] {stage['name']} (exit {code})")
            else:
                print(f"[ok] {stage['name']}")
        record["outputs"] = [
            {
                "path": path,
                "sha256": sha256(REPO_ROOT / path),
                "present": (REPO_ROOT / path).exists(),
                "origin": record["result_origin"],
            }
            for path in stage["outputs"]
        ]
        manifest["stages"].append(record)

    manifest["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["summary"] = {
        "stages_total": len(STAGES),
        "stages_computed": sum(1 for row in manifest["stages"] if row["status"] == "computed"),
        "stages_blocked": blocked,
        "stages_failed": failed,
        "historical_only_outputs": len(HISTORICAL_ONLY),
    }

    manifest_path = REPO_ROOT / args.manifest
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest["summary"], indent=2))
    print(f"provenance manifest: {args.manifest}")

    if failed:
        return 1
    if blocked and not args.allow_blocked:
        print(
            "\nBlocked stages have missing inputs. Fetch published artifacts with:\n"
            f"  {BUNDLE_HINT}\n"
            "or re-run with --allow-blocked to record the gap without failing."
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

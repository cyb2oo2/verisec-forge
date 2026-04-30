from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vrf.io_utils import read_json, read_jsonl


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    path = REPO_ROOT / artifact["path"]
    result: dict[str, Any] = {
        "role": artifact["role"],
        "path": artifact["path"],
        "exists": path.exists(),
    }
    if not path.exists():
        result["status"] = "missing"
        return result
    actual_bytes = path.stat().st_size
    actual_sha256 = sha256_file(path)
    actual_rows = len(read_jsonl(path))
    result.update(
        {
            "expected_bytes": artifact["bytes"],
            "actual_bytes": actual_bytes,
            "expected_rows": artifact["rows"],
            "actual_rows": actual_rows,
            "expected_sha256": artifact["sha256"],
            "actual_sha256": actual_sha256,
            "status": "ok"
            if (
                actual_bytes == int(artifact["bytes"])
                and actual_rows == int(artifact["rows"])
                and actual_sha256.lower() == str(artifact["sha256"]).lower()
            )
            else "mismatch",
        }
    )
    return result


def validate_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [validate_artifact(artifact) for artifact in manifest["artifacts"]]


def build_command(manifest: dict[str, Any], *, json_output: str, md_output: str, predictions_output: str) -> list[str]:
    command = [sys.executable] + list(manifest["command"][1:])
    command.extend(["--json-output", json_output, "--md-output", md_output, "--predictions-output", predictions_output])
    return command


def metric_check(report: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    actual = {
        "selected_bucket_threshold": report["selection"]["bucket_threshold"],
        "eval_balanced_accuracy": report["eval"]["overall"]["balanced_accuracy"],
        "eval_group_all_correct_rate": report["eval"]["group_metrics"]["group_all_correct_rate"],
        "eval_orientation_accuracy": report["eval"]["group_metrics"]["orientation_accuracy"],
        "baseline_eval_balanced_accuracy": report["same_split_controls"]["baseline_direction_aware"]["overall"][
            "balanced_accuracy"
        ],
        "baseline_group_all_correct_rate": report["same_split_controls"]["baseline_direction_aware"]["group_metrics"][
            "group_all_correct_rate"
        ],
        "baseline_orientation_accuracy": report["same_split_controls"]["baseline_direction_aware"]["group_metrics"][
            "orientation_accuracy"
        ],
    }
    checks = {
        key: {
            "expected": expected[key],
            "actual": actual[key],
            "matches": actual[key] == expected[key],
        }
        for key in expected
    }
    return {"actual": actual, "checks": checks, "all_match": all(item["matches"] for item in checks.values())}


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate and reproduce the PrimeVul calibrated bucket-router report.")
    parser.add_argument("--manifest", default="reproducibility/primevul_calibrated_router_manifest.json")
    parser.add_argument("--json-output", default="reports/secure_code_primevul_directional_bucket_router_calibrated_v1_report.json")
    parser.add_argument("--md-output", default="reports/PRIMEVUL_DIRECTIONAL_BUCKET_ROUTER_CALIBRATED.md")
    parser.add_argument("--predictions-output", default="outputs/secure_code_primevul_directional_bucket_router_calibrated_v1_predictions.jsonl")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()

    manifest = read_json(args.manifest)
    artifact_results = validate_manifest(manifest)
    missing_or_bad = [row for row in artifact_results if row["status"] != "ok"]
    if missing_or_bad:
        print(json.dumps({"status": "artifact_validation_failed", "artifacts": artifact_results}, indent=2))
        raise SystemExit(1)

    if args.check_only:
        print(json.dumps({"status": "ok", "artifacts": artifact_results}, indent=2))
        return

    command = build_command(
        manifest,
        json_output=args.json_output,
        md_output=args.md_output,
        predictions_output=args.predictions_output,
    )
    completed = subprocess.run(command, cwd=REPO_ROOT, check=True, capture_output=True, text=True)
    report = read_json(args.json_output)
    checks = metric_check(report, manifest["expected"])
    print(
        json.dumps(
            {
                "status": "ok" if checks["all_match"] else "metric_mismatch",
                "command": command,
                "stdout": completed.stdout,
                "metric_check": checks,
            },
            indent=2,
        )
    )
    if not checks["all_match"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

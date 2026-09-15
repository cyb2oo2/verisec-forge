"""Read-only scientific audit of retained inputs; writes only adjacent audit JSON.

Run from the repository: .venv/Scripts/python.exe reports/scientific_review_2026_09_07/audit_existing_artifacts.py
No training, inference, network calls, or historical artifact edits.
"""
from __future__ import annotations

import collections
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from vrf.repair_evaluation import (
    antisymmetric_inference_correctness,
    compare_antisymmetric_inference,
    evaluate_repair_criteria,
)
from vrf.relational_evaluation import marginal_conditioned_violation_baseline, join_predictions


def read_rows(path):
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8").splitlines() if line.strip()]


def duplicate_join_probe():
    try:
        joined = join_predictions([dict(id="x", runtime_accounting={})],
                                  [dict(id="x", prediction="A"), dict(id="x", prediction="B")])
        return {"rejected": False, "prediction": joined[0]["predicted_riskier_side"]}
    except ValueError as error:
        return {"rejected": True, "error": str(error)}


def main():
    inputs = {
        "audit": "data/processed/secure_code_qwen_mechanism_polarity_only_swap_audit_v1.jsonl",
        "baseline": "outputs/secure_code_qwen_mechanism_polarity_only_swap_audit_v1_predictions_1024.jsonl",
        "repaired": "outputs/secure_code_repair_antisymmetric_polarity_audit_predictions_1024.jsonl",
        "nuisance": "data/processed/secure_code_nuisance_transfer_audit_v1_runtime1024.jsonl",
    }
    raw = {k: read_rows(p) for k, p in inputs.items()}
    audit = raw["audit"]
    baseline = {r["id"]: r for r in raw["baseline"]}
    repaired = {r["id"]: r for r in raw["repaired"]}
    audit_ids = {r["id"] for r in audit}
    integrity = {}
    for name, rows in raw.items():
        integrity[name] = {
            "path": inputs[name], "rows": len(rows),
            "sha256": hashlib.sha256((ROOT / inputs[name]).read_bytes()).hexdigest(),
            "duplicate_ids": len(rows) - len({r["id"] for r in rows}),
        }
    for name, preds in [("baseline", baseline), ("repaired", repaired)]:
        integrity[name].update(missing_ids=len(audit_ids - preds.keys()), extra_ids=len(preds.keys() - audit_ids))
    if any(v["duplicate_ids"] for v in integrity.values()):
        raise ValueError("Duplicate source IDs")
    if any(integrity[n][k] for n in ["baseline", "repaired"] for k in ["missing_ids", "extra_ids"]):
        raise ValueError("Incomplete source predictions")

    by_source = {}
    for source in sorted({r["dataset"] for r in audit}):
        by_source[source] = compare_antisymmetric_inference([r for r in audit if r["dataset"] == source], baseline, repaired)
    visibility = {}
    for variant in sorted({r["audit_variant"] for r in raw["nuisance"]}):
        rows = [r for r in raw["nuisance"] if r["audit_variant"] == variant]
        visibility[variant] = {
            "rows": len(rows),
            "zero_critical_lines": sum(r["runtime_accounting"]["critical_lines_total"] == 0 for r in rows),
            "reported_critical_truncation": sum(r["runtime_accounting"]["critical_hunk_truncated"] for r in rows),
            "input_exceeds_cap": sum(r["runtime_accounting"]["token_count"] > r["runtime_accounting"]["max_length"] for r in rows),
        }

    nulls = {}
    lookup = {(r["pair_key"], r["audit_variant"]): r for r in audit}
    for name, predictions in [("baseline", baseline), ("repaired", repaired)]:
        groups = []
        for variant, relation in [("polarity_only_swap", "invariant"), ("side_swap", "equivariant_swap")]:
            rows = []
            for row in audit:
                if row["audit_variant"] != variant:
                    continue
                canonical = lookup[row["pair_key"], "canonical"]
                rows.append(dict(expected_relation=relation,
                                 base_prediction=predictions[canonical["id"]]["predicted_riskier_side"],
                                 transformed_prediction=predictions[row["id"]]["predicted_riskier_side"],
                                 base_protocol_valid=True, transformed_protocol_valid=True))
            groups.append(rows)
        nulls[name] = {
            "current_pooled": marginal_conditioned_violation_baseline(sum(groups, []))["baseline_violation_rate"],
            "relation_stratified": sum(marginal_conditioned_violation_baseline(g)["baseline_violation_rate"] * len(g) for g in groups) / sum(map(len, groups)),
        }

    toy = [dict(expected_relation=relation, base_prediction="A", transformed_prediction=p,
                base_protocol_valid=True, transformed_protocol_valid=True)
           for relation, p in [("invariant", "A"), ("equivariant_swap", "B")]]
    tie_rows = [dict(id="x", pair_key="p", audit_variant="canonical", gold_riskier_side="A"),
                dict(id="y", pair_key="p", audit_variant="side_swap", gold_riskier_side="B")]
    tie_predictions = {k: {"probability_b": .5} for k in ["x", "y"]}
    counterexamples = {
        "mixed_relation_null": marginal_conditioned_violation_baseline(toy)["baseline_violation_rate"],
        "stratified_relation_null": sum(marginal_conditioned_violation_baseline([r])["baseline_violation_rate"] for r in toy) / 2,
        "tie_forward": antisymmetric_inference_correctness(tie_rows, tie_predictions)["correct_by_pair"],
        "tie_reverse": antisymmetric_inference_correctness(tie_rows, tie_predictions, canonical_variant="side_swap", side_swap_variant="canonical")["correct_by_pair"],
        "duplicate_prediction_join": duplicate_join_probe(),
    }
    cmd = [sys.executable, str(ROOT / "scripts/build_reproducibility_bundle.py")]
    for name in ["veripatch_external_smoke_manifest", "readout_confirmatory_manifest", "frozen_backbone_readout_control_manifest"]:
        cmd.extend(["--manifest", f"reproducibility/{name}.json"])
    proc = subprocess.run(cmd + ["--check-only", "--include-generated"], cwd=ROOT, capture_output=True, text=True, check=False)
    manifest = json.loads(proc.stdout)
    payload = {
        "audit_date": "2026-09-07",
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "scope": "Local artifact reanalysis and code counterexamples; not fresh model inference or independent confirmation",
        "input_integrity": integrity,
        "source_pair_counts": dict(collections.Counter(r["dataset"] for r in audit if r["audit_variant"] == "canonical")),
        "pooled_repair": compare_antisymmetric_inference(audit, baseline, repaired),
        "exploratory_source_breakdown": by_source,
        "raw_repair_gate": evaluate_repair_criteria(audit, repaired, baseline_canonical_accuracy=.66),
        "nuisance_visibility": visibility,
        "null_sensitivity": nulls,
        "synthetic_counterexamples": counterexamples,
        "manifest_check": {"status": manifest["status"], "artifact_count": manifest["artifact_count"],
                           "counts": dict(collections.Counter(c["status"] for c in manifest["checks"])),
                           "failures": [c for c in manifest["checks"] if c["status"] != "ok"]},
    }
    destination = Path(__file__).with_name("audit_recheck.json")
    destination.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(destination), "pooled_repair": payload["pooled_repair"],
                      "raw_repair_passed": payload["raw_repair_gate"]["all_applicable_passed"],
                      "manifest_status": manifest["status"]}, indent=2))


if __name__ == "__main__":
    main()

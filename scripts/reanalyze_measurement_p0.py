"""Offline P0 reanalysis; preserve original data, predictions and reports.

Loads a local tokenizer, never model weights. Writes derived artifacts beneath
reports/scientific_review_2026_09_07/p0 and data/processed/p0_measurement_v2.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
from scripts.build_nuisance_transfer_audit import build_base_pairs
from vrf.io_utils import read_jsonl
from vrf.nuisance_transfer import split_view_occurrences
from vrf.relational_benchmark import swap_pair
from vrf.relational_runtime import runtime_accounting
from vrf.prediction_validation import prediction_index, unique_rows
from vrf.repair_evaluation import compare_antisymmetric_inference, evaluate_repair_criteria
from vrf.relational_evaluation import relation_gap_bootstrap


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main():
    out = ROOT / "reports/scientific_review_2026_09_07/p0"
    out.mkdir(parents=True, exist_ok=True)
    audit_path = ROOT / "data/processed/secure_code_nuisance_transfer_audit_v1_runtime1024.jsonl"
    old_rows = read_jsonl(audit_path)
    unique_rows(old_rows)
    old_rows = [r for r in old_rows if r["audit_family"] == "split_view"]
    pairs, sources = build_base_pairs(limit=200, seed=42)
    pair_index = {(p.dataset, p.pair_key): p for p in pairs}
    from transformers import AutoTokenizer
    tokenizer_path = ROOT / old_rows[0]["runtime_accounting"]["tokenizer_id"]
    tokenizer = AutoTokenizer.from_pretrained(tokenizer_path, local_files_only=True)
    revised = []
    for row in old_rows:
        candidate = pair_index[row["dataset"], row["pair_key"]]
        if row["expected_relation"] != "identity":
            candidate = swap_pair(candidate)
        spans = split_view_occurrences(candidate, row["text"])
        old = row["runtime_accounting"]
        accounting = runtime_accounting(row["text"], tokenizer=tokenizer, model_id=old["model_id"],
            tokenizer_id=old["tokenizer_id"], max_length=old["max_length"],
            truncation_side=old["truncation_side"], add_special_tokens=old["add_special_tokens"],
            changed_occurrences=spans)
        if accounting["token_count"] != old["token_count"]:
            raise ValueError(f"tokenizer/token-count drift: {row['id']}")
        if row["gold_riskier_side"] != candidate.gold_riskier_side:
            raise ValueError("source/gold binding mismatch")
        revised.append({**row, "base_id": f"audit::{row['dataset']}::{row['pair_key']}::canonical__split_view",
                        "rendered_changed_occurrences": spans, "runtime_accounting": accounting})
    by_pair = {(r["dataset"], r["pair_key"], r["audit_variant"]): r for r in revised}
    for r in revised:
        base = by_pair[r["dataset"], r["pair_key"], "canonical__split_view"]
        a = r["runtime_accounting"]
        a["base_critical_hunk_truncated"] = base["runtime_accounting"]["critical_hunk_truncated"]
        a["transformation_introduced_critical_truncation"] = a["critical_hunk_truncated"] and not a["base_critical_hunk_truncated"]
    derived = ROOT / "data/processed/p0_measurement_v2/split_view_runtime1024.jsonl"
    derived.parent.mkdir(parents=True, exist_ok=True)
    derived.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in revised), encoding="utf-8")
    old_by_id = {r["id"]: r for r in old_rows}
    assert all(r["text"] == old_by_id[r["id"]]["text"] and r["gold_riskier_side"] == old_by_id[r["id"]]["gold_riskier_side"] for r in revised)
    canonical = [r for r in revised if r["expected_relation"] == "identity"]
    clean_keys = {(r["dataset"], r["pair_key"]) for r in canonical
                  if not r["runtime_accounting"]["critical_hunk_truncated"]
                  and not by_pair[r["dataset"], r["pair_key"], "side_swap__split_view"]["runtime_accounting"]["critical_hunk_truncated"]}
    clean = [r for r in revised if (r["dataset"], r["pair_key"]) in clean_keys]
    baseline_path = ROOT / "outputs/secure_code_nuisance_transfer_baseline_predictions_1024.jsonl"
    repaired_path = ROOT / "outputs/secure_code_nuisance_transfer_repaired_predictions_1024.jsonl"
    all_ids = [r["id"] for r in read_jsonl(audit_path)]
    baseline = prediction_index(read_jsonl(baseline_path), all_ids)
    repaired = prediction_index(read_jsonl(repaired_path), all_ids)
    comparison = compare_antisymmetric_inference(clean, baseline, repaired,
        canonical_variant="canonical__split_view", side_swap_variant="side_swap__split_view")
    pol_path = ROOT / "data/processed/secure_code_qwen_mechanism_polarity_only_swap_audit_v1.jsonl"
    pol = read_jsonl(pol_path)
    pred_path = ROOT / "outputs/secure_code_repair_antisymmetric_polarity_audit_predictions_1024.jsonl"
    pred = prediction_index(read_jsonl(pred_path), [r["id"] for r in pol])
    pol_base_path = ROOT / "outputs/secure_code_qwen_mechanism_polarity_only_swap_audit_v1_predictions_1024.jsonl"
    pol_base = prediction_index(read_jsonl(pol_base_path), [r["id"] for r in pol])
    pooled_comparison = compare_antisymmetric_inference(pol, pol_base, pred)
    bases = {(r["dataset"], r["pair_key"]): r for r in pol if r["audit_variant"] == "canonical"}
    relations = []
    for r in pol:
        if r["audit_variant"] == "canonical":
            continue
        base = bases[r["dataset"], r["pair_key"]]
        a, b = pred[base["id"]]["predicted_riskier_side"], pred[r["id"]]["predicted_riskier_side"]
        relation = r["expected_relation"]
        relations.append(dict(dataset=r["dataset"], pair_key=r["pair_key"], expected_relation=relation,
            transformation_family=r["audit_family"], base_prediction=a, transformed_prediction=b,
            base_protocol_valid=True, transformed_protocol_valid=True,
            relation_success=a == b if relation == "invariant" else a != b))

    # Recover the exact original bytes from a local historical bundle, without
    # overwriting the current worktree evidence or modifying its expected hash.
    cache = "reports/secure_code_frozen_readout_control_train_cache_v1.json"
    zip_path = ROOT / "artifacts/verisec_forge_frozen_backbone_readout_control_v1.zip"
    with zipfile.ZipFile(zip_path) as archive:
        original = archive.read(cache)
    current = (ROOT / cache).read_bytes()
    assert hashlib.sha256(original).hexdigest() == "22b45a854004be6bf46f413d0eb8d2a8ed236043ea6b4f697a6c7bc87e452060"
    assert original.replace(b"\r\n", b"\n") == current.replace(b"\r\n", b"\n")
    recovered = out / "frozen_train_cache_original.json"
    recovered.write_bytes(original)
    artifacts = []
    for name in ["veripatch_external_smoke_manifest", "readout_confirmatory_manifest", "frozen_backbone_readout_control_manifest"]:
        manifest = json.loads((ROOT / f"reproducibility/{name}.json").read_text(encoding="utf-8"))
        for artifact in manifest.get("artifacts", []) + manifest.get("generated_artifacts", []):
            if artifact["path"] == cache:
                artifact = {**artifact, "path": recovered.relative_to(ROOT).as_posix()}
            artifacts.append(artifact)
    write(out / "recovered_inputs_manifest.json", {"name": "p0_recovered_inputs", "artifacts": artifacts,
        "note": "Exact bundle bytes substituted only for the mixed-line-ending report; original manifests and evidence unchanged."})
    proc = subprocess.run([sys.executable, str(ROOT / "scripts/build_reproducibility_bundle.py"),
        "--manifest", str(out / "recovered_inputs_manifest.json"), "--check-only"], cwd=ROOT, capture_output=True, text=True)
    validation = json.loads(proc.stdout)
    result = {"status": "ok" if proc.returncode == 0 else "failed", "new_model_inference": False,
        "scope": "Post-review exploratory reanalysis; no preregistered threshold changed or new confirmation claimed.",
        "source_pair_sampling": sources,
        "split_view": {"rows": len(revised), "texts_and_gold_unchanged": True,
            "token_counts_match_original": True, "zero_changed_line_rows": sum(r["runtime_accounting"]["critical_lines_total"] == 0 for r in revised),
            "truncated_rows": sum(r["runtime_accounting"]["critical_hunk_truncated"] for r in revised),
            "fully_visible_pairs": len(clean_keys), "total_pairs": len(canonical),
            "clean_pair_projection_comparison": comparison,
            "boundary": "Visibility of changed lines only; split-view information equivalence remains unestablished."},
        "pooled_projection_v2": pooled_comparison,
        "raw_repair_gate_v2": evaluate_repair_criteria(pol, pred, baseline_canonical_accuracy=.66),
        "raw_repair_relation_gap": relation_gap_bootstrap(relations, iterations=2000, seed=42),
        "cache_mismatch_diagnosis": {"cause": "line endings only", "json_identical": json.loads(original) == json.loads(current),
            "original_sha256": hashlib.sha256(original).hexdigest(), "current_sha256": hashlib.sha256(current).hexdigest(),
            "original_crlf": original.count(b"\r\n"), "current_crlf": current.count(b"\r\n"),
            "bundle_sha256": sha(zip_path), "original_file_preserved": True},
        "recovered_manifest": {"status": validation["status"], "artifacts": validation["artifact_count"]},
        "input_hashes": {p.relative_to(ROOT).as_posix(): sha(p) for p in [audit_path, baseline_path, repaired_path, pol_path, pred_path, pol_base_path]},
        "tokenizer_hashes": {p.name: sha(p) for p in tokenizer_path.glob("*token*.json")},
        "implementation_hashes": {p: sha(ROOT / p) for p in ["src/vrf/relational_runtime.py", "src/vrf/nuisance_transfer.py", "src/vrf/repair_evaluation.py", "src/vrf/relational_evaluation.py", "src/vrf/prediction_validation.py", "scripts/reanalyze_measurement_p0.py"]},
        "derived_runtime": {"path": derived.relative_to(ROOT).as_posix(), "sha256": sha(derived)}}
    write(out / "results.json", result)
    print(json.dumps({k: result[k] for k in ["status", "split_view", "raw_repair_relation_gap", "cache_mismatch_diagnosis", "recovered_manifest"]}, indent=2))


if __name__ == "__main__":
    main()

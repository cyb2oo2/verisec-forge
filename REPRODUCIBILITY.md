# Reproducibility

This repository separates committed research reports from large local experiment artifacts.

The current most reproducible mainline is the validation-selected PrimeVul direction-aware bucket router. It does not require GPU training if the required dataset and prediction artifacts are already materialized locally.

## Quick Check

Run the full test suite:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests
```

Validate that the required router artifacts are present and match the recorded hashes:

```powershell
.\.venv\Scripts\python.exe scripts\reproduce_primevul_calibrated_router.py --check-only
```

Reproduce the calibrated router report:

```powershell
.\.venv\Scripts\python.exe scripts\reproduce_primevul_calibrated_router.py
```

Expected key outputs:

- selected bucket threshold: `0.7`
- held-out eval balanced accuracy: `0.8136`
- held-out eval group all-correct rate: `0.7117`
- held-out eval orientation accuracy: `0.8581`
- same-split baseline group all-correct rate: `0.7101`
- same-split baseline orientation accuracy: `0.8514`

## Evidence-Coupled Reproduction

The current evidence-coupled chain can also be reproduced without GPU training once its local candidate and prediction artifacts exist:

```powershell
.\.venv\Scripts\python.exe scripts\reproduce_primevul_evidence_coupled.py --check-only
.\.venv\Scripts\python.exe scripts\reproduce_primevul_evidence_coupled.py
```

Expected key outputs:

- hunk+window linear top-1 coverage: `0.6178`
- oracle side-aware matched top-1 coverage: `0.7184`
- pair-coupled predicted-side top-1 coverage: `0.6555`
- pair-coupled side accuracy: `0.8488`
- side-wrong rows: `190`
- confident inversion rows at `gap >= 0.50`: `86`
- pair-side correction seed42 balanced accuracy: `0.8470 -> 0.8481`
- pair-side correction multi-split balanced-accuracy delta mean: `0.0000`
- contrastive side-correction multi-split balanced-accuracy delta mean: `-0.0002`
- paired-window contrastive rows: `592`
- paired-window label-B orientation inversions: `83`
- paired-window high-gap orientation inversion pairs: `44`
- paired-window side-model balanced accuracy mean: `0.6065`
- paired-window side-model label-B recall mean: `0.4367`
- paired-window side-model top-5 flip precision mean: `0.7200`
- side-inversion review queue rows / precision: `25` / `0.7200`
- side-inversion verifier rows / accept / reject: `25` / `18` / `7`
- side-inversion verifier average prompt chars: `2873.2`
- side-inversion verifier baseline best balanced accuracy / accept precision: `0.7778` / `1.0000`
- side-inversion verifier baseline accepted flips: `10`
- side-inversion strict safe flip gate accepted rows / unique pairs: `10` / `4`
- side-inversion strict safe flip gate repaired / introduced rows: `10` / `0`
- side-inversion rank-holdout queue precision: `0.3200`
- side-inversion rank-holdout strict safe flip gate accepted / introduced rows: `2` / `0`
- side-inversion fresh-seed queue precision: `0.5200`
- side-inversion fresh-seed default gate accept precision / introduced rows: `0.9000` / `1`
- side-inversion fresh-seed strict gate accept precision / introduced rows: `1.0000` / `0`
- side-inversion project-heldout queue precision: `0.4800`
- side-inversion project-heldout strict gate accept precision / introduced rows: `0.7500` / `3`
- side-inversion project-heldout evidence-conditioned gate accept precision / introduced rows: `1.0000` / `0`
- side-inversion gate summary reports / pools / zero-introduced / stress-invalidated reports: `6` / `4` / `5` / `1`
- side-inversion gate summary selection-allowed / audit-only reports: `1` / `5`
- side-inversion gate summary protocol violations: `0`
- side-inversion project-heldout conservative gate accept precision / introduced rows: `1.0000` / `0`

The exact local inputs and expected generated artifacts are listed in:

- `reproducibility/primevul_evidence_coupled_manifest.json`

## Required Artifacts

The exact local artifacts are listed in:

- `reproducibility/primevul_calibrated_router_manifest.json`

The manifest records:

- path
- role
- byte size
- row count
- SHA256
- expected reproduced metrics

These files are intentionally not committed because `data/processed` and `outputs` are gitignored:

- `data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl`
- `outputs/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_3000_v1_eval1792_dedup_predictions.jsonl`
- `outputs/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_recall_recovery_3249_v1_eval1792_dedup_predictions.jsonl`
- `data/processed/primevul_candidate_recall_train_v1/hunk_plus_window_candidates.jsonl`
- `data/processed/primevul_candidate_recall_eval_v1/hunk_plus_window_candidates.jsonl`
- `outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl`
- `data/processed/secure_code_primevul_paired_window_contrastive_eval_v1.jsonl`
- `data/processed/secure_code_primevul_side_inversion_review_queue_top5_v1.jsonl`
- `data/processed/secure_code_primevul_side_inversion_verifier_top5_v1.jsonl`
- `outputs/secure_code_primevul_side_inversion_safe_flip_gate_top5_v1_accepted.jsonl`
- `data/processed/secure_code_primevul_side_inversion_review_queue_rank6_10_v1.jsonl`
- `data/processed/secure_code_primevul_side_inversion_verifier_rank6_10_v1.jsonl`
- `outputs/secure_code_primevul_side_inversion_safe_flip_gate_rank6_10_v1_accepted.jsonl`

If a fresh clone is missing these files, the reproduction script fails with a structured missing-artifact report instead of silently producing partial results.

## Artifact Bundle Workflow

The manifests can now be checked or packaged with a shared bundle utility:

```powershell
.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py --manifest reproducibility\primevul_evidence_coupled_manifest.json --check-only
```

To create a local shareable zip:

```powershell
.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py `
  --manifest reproducibility\primevul_calibrated_router_manifest.json `
  --manifest reproducibility\primevul_evidence_coupled_manifest.json `
  --output artifacts\verisec_forge_primevul_repro_bundle.zip
```

The zip includes `BUNDLE_MANIFEST.json` plus the manifest-listed local inputs. The default output directory is `artifacts/`, which is intentionally gitignored.

To restore a bundle into a fresh clone:

```powershell
.\.venv\Scripts\python.exe scripts\restore_reproducibility_bundle.py --bundle artifacts\verisec_forge_primevul_repro_bundle.zip
```

See `reproducibility/ARTIFACT_BUNDLE.md` for the full reviewer workflow and current boundary.

## Main Reports

The calibrated router report is:

- `reports/PRIMEVUL_DIRECTIONAL_BUCKET_ROUTER_CALIBRATED.md`
- `reports/secure_code_primevul_directional_bucket_router_calibrated_v1_report.json`

The project-level summary table is regenerated by:

```powershell
.\.venv\Scripts\python.exe scripts\build_primevul_main_results.py
.\.venv\Scripts\python.exe scripts\build_primevul_main_results_chart.py
```

## Current Limitation

This is not yet a fully fresh-clone reproduction of every experiment. The repository now has a local artifact-bundle builder, verifier, and restore path, but the bundle still needs to be published to a stable external artifact host before a fresh clone can materialize all exact inputs without local state.

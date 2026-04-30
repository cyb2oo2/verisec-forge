# Data Lineage

This document tracks the current mainline data flow for the PrimeVul paired diff reasoning experiments.

## Source

- Upstream dataset family: `PrimeVul`
- Project use: defensive secure-code reasoning and patch/diff vulnerability judgment
- Main task: decide whether the candidate side of a paired diff is the vulnerable version

## Current Mainline Artifacts

### Paired Diff Eval

- Local path: `data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl`
- Rows: `1792`
- SHA256: `7bc138be4e24fdd91d2d7d9ba2b03e6c57df287ad31e3ff3b76656c4713c7bb9`
- Role: deduplicated paired diff eval rows with `pair_key`, metadata, labels, and unified diff prompt text

### Baseline Direction-Aware Predictions

- Local path: `outputs/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_3000_v1_eval1792_dedup_predictions.jsonl`
- Rows: `1792`
- SHA256: `11137e2ef52c0951a98d86ac38f246f64d22366b0df04ae34f896c5157d4b4e3`
- Role: predictions from the baseline direction-aware detector

### Recall-Recovery Predictions

- Local path: `outputs/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_recall_recovery_3249_v1_eval1792_dedup_predictions.jsonl`
- Rows: `1792`
- SHA256: `841215cee202ed45226a868041b4a17a0be90f076b310b7f30faf883c81d4b54`
- Role: predictions from the direction-aware recall-recovery v1 detector

## Validation-Selected Router

The calibrated router uses:

- `30%` of pair groups for calibration
- `70%` held-out pair groups for reporting
- split seed `42`
- selector `balanced_accuracy`
- candidate bucket thresholds `0.5, 0.6, 0.7, 0.8, 0.9`

Selected threshold:

- `26+` bucket threshold: `0.8`

Held-out result:

- balanced accuracy: `0.8136`
- group all-correct rate: `0.7117`
- orientation accuracy: `0.8581`

Same-split baseline control:

- balanced accuracy: `0.8136`
- group all-correct rate: `0.7101`
- orientation accuracy: `0.8514`

## Interpretation Boundary

The router result should be interpreted as a calibration and pair-consistency improvement, not as a new raw detection breakthrough. It slightly improves pair/group metrics while keeping row-level balanced accuracy flat on the held-out split.

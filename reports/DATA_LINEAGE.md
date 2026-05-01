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

- `26+` bucket threshold: `0.7`

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

## Pair Evidence Localization

The first evidence-localization layer uses the pair-coupled held-out predictions and extracts heuristic hunk-level support scores. It is not gold evidence-span supervision.

- Report: `reports/PRIMEVUL_PAIR_EVIDENCE_LOCALIZATION.md`
- JSON summary: `reports/secure_code_primevul_pair_evidence_localization_v1.json`
- JSON summary SHA256: `8150eb893decefa60354c7c2de47450a0d93b28a94ff148a5fff02a0ff2b4dc3`
- Row-level output: `outputs/secure_code_primevul_pair_evidence_localization_v1.jsonl`
- Row-level output rows: `1261`
- support rate: `0.6376`
- pseudo-localization accuracy: `0.6003`
- vulnerable pseudo-localization accuracy: `0.5952`
- safe pseudo-localization accuracy: `0.6054`
- best hunk-limit sweep pseudo-localization accuracy: `0.6051` at top-3 hunks
- supported prediction error rate: `0.0933`
- unsupported prediction error rate: `0.2516`

## Hunk Pseudo-Label Datasets

These artifacts convert paired diffs into hunk-level pseudo labels for cheap localizer experiments. They are not human evidence annotations.

Train:

- Source: `data/processed/secure_code_primevul_pair_diff_only_train_balanced_3000_metadata.jsonl`
- Output: `data/processed/secure_code_primevul_hunk_pseudo_train_top8.jsonl`
- Summary: `reports/PRIMEVUL_HUNK_PSEUDO_LABEL_TRAIN.md`
- Hunk rows: `4697`
- Source rows: `2999`
- Positive hunk rate: `0.4788`
- top-1 / top-8 coverage: `0.5575` / `0.5822`

Eval:

- Source: `data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl`
- Output: `data/processed/secure_code_primevul_hunk_pseudo_eval_top8.jsonl`
- Summary: `reports/PRIMEVUL_HUNK_PSEUDO_LABEL_EVAL.md`
- Hunk rows: `2536`
- Source rows: `1787`
- Positive hunk rate: `0.5335`
- top-1 / top-8 coverage: `0.5792` / `0.6150`

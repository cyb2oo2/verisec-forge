# PatchEval Source-Specific Adapter Seed7 Pair-Diff Evaluation

This report evaluates paired-diff detector predictions on `ByteDance/PatchEval` paired vulnerable/secure snapshots.
Target training: PatchEval train split only.

## Protocol

- Source dataset: `ByteDance/PatchEval`
- Checkpoint: `cls_secure_code_patcheval_qwen15bcoder_lora_pair_diff_seed7_v1`
- Threshold: `0.5`
- Pair-coupling margin: `0.02`

## Split

- Rows: `538`
- Pair groups: `269`
- Safe/vulnerable: `269/269`

## Results

| System | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.7993` | `0.7732` | `0.8253` | `0.8157` | `0.7939` | `0.7026` | `0.8141` |
| `pair-coupled` | `0.8197` | `0.8141` | `0.8253` | `0.8233` | `0.8187` | `0.8104` | `0.8141` |

## Interpretation

This is a cross-source paired-diff transfer check. If it is much lower than PrimeVul, that is useful negative evidence: the system has learned the PrimeVul paired-diff formulation, but cross-dataset patch semantics may need source-specific calibration, source-aware adapters, or a mixed-source detector.

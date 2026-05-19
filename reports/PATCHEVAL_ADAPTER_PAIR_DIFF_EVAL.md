# PatchEval Source-Specific Adapter Pair-Diff Evaluation

This report evaluates paired-diff detector predictions on `ByteDance/PatchEval` paired vulnerable/secure snapshots.
Target training: PatchEval train split only.

## Protocol

- Source dataset: `ByteDance/PatchEval`
- Checkpoint: `cls_secure_code_patcheval_qwen15bcoder_lora_pair_diff_v1`
- Threshold: `0.5`
- Pair-coupling margin: `0.02`

## Split

- Rows: `538`
- Pair groups: `269`
- Safe/vulnerable: `269/269`

## Results

| System | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.8011` | `0.7732` | `0.829` | `0.8189` | `0.7954` | `0.7026` | `0.8364` |
| `pair-coupled` | `0.829` | `0.8253` | `0.8327` | `0.8315` | `0.8284` | `0.8141` | `0.8364` |

## Interpretation

This is a cross-source paired-diff transfer check. If it is much lower than PrimeVul, that is useful negative evidence: the system has learned the PrimeVul paired-diff formulation, but cross-dataset patch semantics may need source-specific calibration, source-aware adapters, or a mixed-source detector.

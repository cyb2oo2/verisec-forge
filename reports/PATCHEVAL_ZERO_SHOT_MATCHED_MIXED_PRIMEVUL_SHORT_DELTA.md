# PatchEval Zero-Shot Matched Mixed-Source Pair-Diff Evaluation

This report evaluates paired-diff detector predictions on `ByteDance/PatchEval` paired vulnerable/secure snapshots.
Target training: short PrimeVul time train + DeltaSecommits C/C++ train.

## Protocol

- Source dataset: `ByteDance/PatchEval`
- Checkpoint: `cls_secure_code_matched_mixed_primevul_time_short_deltasecommits_qwen15bcoder_lora_pair_diff_v1`
- Threshold: `0.5`
- Pair-coupling margin: `0.02`

## Split

- Rows: `538`
- Pair groups: `269`
- Safe/vulnerable: `269/269`

## Results

| System | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.7955` | `0.7509` | `0.8401` | `0.8245` | `0.786` | `0.7361` | `0.8104` |
| `pair-coupled` | `0.8086` | `0.803` | `0.8141` | `0.812` | `0.8075` | `0.7993` | `0.8104` |

## Interpretation

This is a cross-source paired-diff transfer check. If it is much lower than PrimeVul, that is useful negative evidence: the system has learned the PrimeVul paired-diff formulation, but cross-dataset patch semantics may need source-specific calibration, source-aware adapters, or a mixed-source detector.

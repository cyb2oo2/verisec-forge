# PatchEval Adapter on PrimeVul Later-CVE Pair-Diff Evaluation

This report evaluates paired-diff detector predictions on `PrimeVul-time-ge2021` paired vulnerable/secure snapshots.
Target training: PatchEval train split only; cross-source evaluation on PrimeVul later-CVE.

## Protocol

- Source dataset: `PrimeVul-time-ge2021`
- Checkpoint: `cls_secure_code_patcheval_qwen15bcoder_lora_pair_diff_v1`
- Threshold: `0.5`
- Pair-coupling margin: `0.02`

## Split

- Rows: `1562`
- Pair groups: `761`
- Safe/vulnerable: `781/781`

## Results

| System | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.8175` | `0.872` | `0.7631` | `0.7864` | `0.827` | `0.6912` | `0.8712` |
| `pair-coupled` | `0.8521` | `0.8976` | `0.8067` | `0.8228` | `0.8585` | `0.795` | `0.8712` |

## Interpretation

This is a cross-source paired-diff transfer check. If it is much lower than PrimeVul, that is useful negative evidence: the system has learned the PrimeVul paired-diff formulation, but cross-dataset patch semantics may need source-specific calibration, source-aware adapters, or a mixed-source detector.

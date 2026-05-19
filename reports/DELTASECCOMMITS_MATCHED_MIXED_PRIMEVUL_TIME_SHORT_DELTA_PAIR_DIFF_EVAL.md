# DeltaSecommits Matched Mixed-Source Pair-Diff Evaluation

This report evaluates paired-diff detector predictions on DeltaSecommits C/C++ paired vulnerable/secure snapshots.
Target training: short PrimeVul time train + DeltaSecommits C/C++ train.

## Protocol

- Source dataset: `rufimelo/DeltaSecommits`
- Checkpoint: `cls_secure_code_matched_mixed_primevul_time_short_deltasecommits_qwen15bcoder_lora_pair_diff_v1`
- Threshold: `0.5`
- Pair-coupling margin: `0.02`

## Split

- Rows: `654`
- Pair groups: `327`
- Safe/vulnerable: `327/327`

## Results

| System | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.8471` | `0.8043` | `0.8899` | `0.8796` | `0.8403` | `0.7798` | `0.8471` |
| `pair-coupled` | `0.8486` | `0.844` | `0.8532` | `0.8519` | `0.8479` | `0.844` | `0.8471` |

## Interpretation

This is the first true cross-source paired-diff transfer check. If it is much lower than PrimeVul, that is useful negative evidence: the system has learned the PrimeVul paired-diff formulation, but cross-dataset patch semantics may need source-specific calibration or a mixed-source detector.

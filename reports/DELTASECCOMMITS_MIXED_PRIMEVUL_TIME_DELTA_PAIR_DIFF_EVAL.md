# DeltaSecommits Mixed-Source Pair-Diff Evaluation

This report evaluates paired-diff detector predictions on DeltaSecommits C/C++ paired vulnerable/secure snapshots.
Target training: PrimeVul time train + DeltaSecommits C/C++ train.

## Protocol

- Source dataset: `rufimelo/DeltaSecommits`
- Checkpoint: `cls_secure_code_mixed_primevul_time_deltasecommits_qwen15bcoder_lora_pair_diff_v1`
- Threshold: `0.5`
- Pair-coupling margin: `0.02`

## Split

- Rows: `654`
- Pair groups: `327`
- Safe/vulnerable: `327/327`

## Results

| System | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.8532` | `0.8318` | `0.8746` | `0.869` | `0.85` | `0.792` | `0.8471` |
| `pair-coupled` | `0.8456` | `0.8379` | `0.8532` | `0.8509` | `0.8444` | `0.8349` | `0.8471` |

## Interpretation

This is the first true cross-source paired-diff transfer check. If it is much lower than PrimeVul, that is useful negative evidence: the system has learned the PrimeVul paired-diff formulation, but cross-dataset patch semantics may need source-specific calibration or a mixed-source detector.

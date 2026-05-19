# DeltaSecommits Delta-Only Pair-Diff Evaluation

This report evaluates paired-diff detector predictions on DeltaSecommits C/C++ paired vulnerable/secure snapshots.
Target training: DeltaSecommits C/C++ train split only.

## Protocol

- Source dataset: `rufimelo/DeltaSecommits`
- Checkpoint: `cls_secure_code_deltasecommits_qwen15bcoder_lora_pair_diff_cpp_v1`
- Threshold: `0.5`
- Pair-coupling margin: `0.02`

## Split

- Rows: `654`
- Pair groups: `327`
- Safe/vulnerable: `327/327`

## Results

| System | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.8517` | `0.8226` | `0.8807` | `0.8734` | `0.8472` | `0.7798` | `0.8563` |
| `pair-coupled` | `0.8563` | `0.8532` | `0.8593` | `0.8585` | `0.8558` | `0.8471` | `0.8563` |

## Interpretation

This is the first true cross-source paired-diff transfer check. If it is much lower than PrimeVul, that is useful negative evidence: the system has learned the PrimeVul paired-diff formulation, but cross-dataset patch semantics may need source-specific calibration or a mixed-source detector.

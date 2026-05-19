# DeltaSecommits Zero-Shot Transfer Evaluation

This report evaluates a PrimeVul-trained paired-diff detector directly on DeltaSecommits C/C++ paired vulnerable/secure snapshots.
No DeltaSecommits training is used here; this is a cross-source transfer stress test.

## Protocol

- Source dataset: `rufimelo/DeltaSecommits`
- Checkpoint: `cls_secure_code_primevul_qwen15bcoder_lora_pair_diff_time_le2020_v1`
- Threshold: `0.5`
- Pair-coupling margin: `0.02`

## Split

- Rows: `3268`
- Pair groups: `1634`
- Safe/vulnerable: `1634/1634`

## Results

| System | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.836` | `0.7662` | `0.9058` | `0.8905` | `0.8237` | `0.743` | `0.866` |
| `pair-coupled` | `0.8641` | `0.8605` | `0.8678` | `0.8668` | `0.8636` | `0.8556` | `0.866` |

## Interpretation

This is the first true cross-source paired-diff transfer check. The result is strong enough to support the paired-diff formulation beyond PrimeVul, while still staying conservative: DeltaSecommits is shorter and cleaner than PrimeVul, so the next ablation should compare zero-shot transfer against mixed-source or Delta-specific training rather than treating this as a universal vulnerability-scanning result.

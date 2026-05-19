# PatchEval Adapter on DeltaSecommits Pair-Diff Evaluation

This report evaluates paired-diff detector predictions on `rufimelo/DeltaSecommits` paired vulnerable/secure snapshots.
Target training: PatchEval train split only; cross-source evaluation on DeltaSecommits.

## Protocol

- Source dataset: `rufimelo/DeltaSecommits`
- Checkpoint: `cls_secure_code_patcheval_qwen15bcoder_lora_pair_diff_v1`
- Threshold: `0.5`
- Pair-coupling margin: `0.02`

## Split

- Rows: `654`
- Pair groups: `327`
- Safe/vulnerable: `327/327`

## Results

| System | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.7859` | `0.8563` | `0.7156` | `0.7507` | `0.8` | `0.6453` | `0.8379` |
| `pair-coupled` | `0.844` | `0.844` | `0.844` | `0.844` | `0.844` | `0.8349` | `0.8379` |

## Interpretation

This is a cross-source paired-diff transfer check. If it is much lower than PrimeVul, that is useful negative evidence: the system has learned the PrimeVul paired-diff formulation, but cross-dataset patch semantics may need source-specific calibration, source-aware adapters, or a mixed-source detector.

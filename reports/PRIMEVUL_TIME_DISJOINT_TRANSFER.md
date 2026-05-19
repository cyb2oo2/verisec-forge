# PrimeVul Time-Disjoint Transfer Evaluation

This report evaluates the original paired-diff detector checkpoint on the true CVE-year time-disjoint eval split.
No retraining is performed here; this is a temporal transfer baseline.

## Split

- Rows: `1562`
- Unique pair groups: `761`
- CVE years: `[2021, 2022]`

## Results

| System | Threshold | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.5` | `0.8348` | `0.8566` | `0.8131` | `0.8209` | `0.8383` | `` | `` |
| `selected threshold` | `0.6` | `0.8412` | `0.8335` | `0.8489` | `0.8466` | `0.84` | `` | `` |
| `pair-coupled` | `0.6` | `0.8745` | `0.8643` | `0.8848` | `0.8824` | `0.8732` | `0.8555` | `0.8752` |

## Delta

- Pair-coupled minus selected-threshold BA: `0.0333`
- Pair-coupled minus selected-threshold group all-correct: `0.1144`
- Pair-coupled minus selected-threshold orientation: `0.0`

## Interpretation

The old paired-diff detector transfers strongly to later CVE years. Pair-coupling is still useful for group consistency, but this transfer run should be treated as a baseline before training directly on the time-disjoint split.

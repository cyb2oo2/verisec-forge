# PrimeVul Time-Disjoint Transfer Evaluation

This report evaluates the matched short PrimeVul + DeltaSecommits paired-diff checkpoint on the true PrimeVul later-CVE time-disjoint eval split.

## Split

- Rows: `1562`
- Unique pair groups: `761`
- CVE years: `[2021, 2022]`

## Results

| System | Threshold | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.5` | `0.8694` | `0.8438` | `0.895` | `0.8893` | `0.866` | `` | `` |
| `selected threshold` | `0.4` | `0.8732` | `0.8681` | `0.8784` | `0.8771` | `0.8726` | `` | `` |
| `pair-coupled` | `0.4` | `0.8809` | `0.8758` | `0.886` | `0.8849` | `0.8803` | `0.8673` | `0.883` |

## Delta

- Pair-coupled minus selected-threshold BA: `0.0077`
- Pair-coupled minus selected-threshold group all-correct: `0.0513`
- Pair-coupled minus selected-threshold orientation: `0.0`

## Interpretation

This report uses the true CVE-year time-disjoint eval split. The selected threshold is chosen from the supplied threshold sweep, and pair-coupled decoding is evaluated as a structured inference layer over paired vulnerable/fixed groups.

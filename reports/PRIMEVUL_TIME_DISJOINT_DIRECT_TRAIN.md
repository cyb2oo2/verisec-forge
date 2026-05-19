# PrimeVul Time-Disjoint Direct-Train Evaluation

This report evaluates a paired-diff detector trained only on CVE-year <=2020 PrimeVul pairs and evaluated on the true CVE-year >=2021 split.

## Split

- Rows: `1562`
- Unique pair groups: `761`
- CVE years: `[2021, 2022]`

## Results

| System | Threshold | BA | Recall | Specificity | Precision | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `default threshold` | `0.5` | `0.872` | `0.8604` | `0.8835` | `0.8807` | `0.8705` | `` | `` |
| `selected threshold` | `0.6` | `0.8745` | `0.8476` | `0.9014` | `0.8958` | `0.8711` | `` | `` |
| `pair-coupled` | `0.6` | `0.8835` | `0.8796` | `0.8873` | `0.8865` | `0.883` | `0.8765` | `0.883` |

## Delta

- Pair-coupled minus selected-threshold BA: `0.009`
- Pair-coupled minus selected-threshold group all-correct: `0.0473`
- Pair-coupled minus selected-threshold orientation: `0.0`

## Interpretation

This report uses the true CVE-year time-disjoint eval split. The selected threshold is chosen from the supplied threshold sweep, and pair-coupled decoding is evaluated as a structured inference layer over paired vulnerable/fixed groups.

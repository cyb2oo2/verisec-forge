# PrimeVul Time-Disjoint Transfer vs Direct Training

This report compares two temporal-generalization settings on the same true CVE-year split:

- Train side: `<=2020`
- Eval side: `>=2021`
- Eval rows: `1562`
- Eval pair groups: `761`
- CVE/CVE-year/pair-key overlap: `0`

## Results

| System | Train Source | Selected-Threshold BA | Pair-Coupled BA | Group All-Correct | Orientation |
| --- | --- | ---: | ---: | ---: | ---: |
| Transfer baseline | original paired-diff train split | `0.8412` | `0.8745` | `0.8555` | `0.8752` |
| Direct time-split train | CVE-year `<=2020` | `0.8745` | `0.8835` | `0.8765` | `0.8830` |

## Direct Minus Transfer

- Selected-threshold BA: `+0.0333`
- Pair-coupled BA: `+0.0090`
- Group all-correct: `+0.0210`
- Orientation accuracy: `+0.0078`

## Interpretation

Direct temporal training improves the standalone selected-threshold detector and slightly improves the pair-coupled system. The important research claim is now stronger: paired diff reasoning is not only a same-source artifact and not only a zero-retraining transfer artifact. It survives a true CVE-year split and improves further when trained on the pre-2021 side.

This should still be framed conservatively. The result supports temporal robustness on PrimeVul paired diffs, not a claim that the model is a general standalone vulnerability scanner.

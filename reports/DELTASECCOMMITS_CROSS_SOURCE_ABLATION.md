# DeltaSecommits Cross-Source Ablation

This report compares matched DeltaSecommits eval-split settings. It is the project first true second-source paired-patch validation table.

## Results

| System | Training data | Rows/Pairs | Default BA | Recall | Specificity | Pair-Coupled BA | Group All-Correct | Orientation | Best Threshold BA |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `PrimeVul zero-shot` | PrimeVul time-disjoint only | `654/327` | `0.8333` | `0.7492` | `0.9174` | `0.8486` | `0.8410` | `0.8471` | `n/a` |
| `Delta-only` | DeltaSecommits C/C++ train | `654/327` | `0.8517` | `0.8226` | `0.8807` | `0.8563` | `0.8471` | `0.8563` | `0.8517` |
| `PrimeVul+Delta mixed` | PrimeVul time-disjoint + DeltaSecommits C/C++ train | `654/327` | `0.8532` | `0.8318` | `0.8746` | `0.8456` | `0.8349` | `0.8471` | `0.8563` |
| `PrimeVul-short+Delta matched` | Short PrimeVul time-disjoint + DeltaSecommits C/C++ train | `654/327` | `0.8471` | `0.8043` | `0.8899` | `0.8486` | `0.8440` | `0.8471` | `0.8670` |

## Interpretation

- PrimeVul zero-shot remains strong on a second paired-patch source, especially after pair-coupled decoding.
- Delta-only training improves the default detector slightly, but not by a large margin, which supports cross-source transfer rather than pure dataset memorization.
- Full PrimeVul+Delta mixed training does not materially beat Delta-only on Delta eval, which argues against indiscriminate source mixing.
- Matched/short mixed-source training improves the calibrated single-row operating point, but it still does not beat Delta-only on pair-coupled consistency; the next useful direction is domain-aware mixing/adapters rather than simply adding more source rows.

## Notes

- `PrimeVul zero-shot`: No DeltaSecommits training; fair eval-split slice of the external transfer run.
- `Delta-only`: Source-specific adaptation baseline.
- `PrimeVul+Delta mixed`: Full mixed-source training; tests whether adding PrimeVul helps Delta beyond Delta-only.
- `PrimeVul-short+Delta matched`: Matched/short mixed-source training removes the PrimeVul extreme prompt-length tail before mixing.

# PrimeVul Router Statistical Analysis

This report estimates uncertainty for the validation-selected bucket router on held-out pair groups.

## Bootstrap 95% Confidence Intervals

| system | metric | observed | ci95_low | ci95_high | units |
| --- | --- | ---: | ---: | ---: | ---: |
| baseline | group_all_correct | 0.7101 | 0.6743 | 0.7443 | 614 |
| baseline | orientation | 0.8514 | 0.8217 | 0.879 | 592 |
| router | group_all_correct | 0.7134 | 0.6792 | 0.7476 | 614 |
| router | orientation | 0.8581 | 0.8289 | 0.8844 | 592 |

## Router Minus Baseline

| metric | delta | ci95_low | ci95_high | sign wins | sign losses | sign p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| group_all_correct | 0.0033 | -0.0065 | 0.0147 | 6 | 4 | 0.753906 |
| orientation | 0.0068 | 0.0017 | 0.0151 | 4 | 0 | 0.125 |

## Interpretation

The router's observed gains are small. They should be treated as pair-consistency evidence, not as a statistically decisive detector improvement unless the confidence intervals and sign tests support that claim on larger or external splits.

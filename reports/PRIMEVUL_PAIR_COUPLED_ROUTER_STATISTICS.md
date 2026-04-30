# PrimeVul Pair-Coupled Router Statistics

This report compares the validation-selected bucket router against pair-coupled decoding on the same held-out pair groups.

## Bootstrap 95% Confidence Intervals

| system | metric | observed | ci95_low | ci95_high | units |
| --- | --- | ---: | ---: | ---: | ---: |
| bucket_router | group_all_correct | 0.7117 | 0.6759 | 0.746 | 614 |
| bucket_router | orientation | 0.8581 | 0.8289 | 0.8844 | 592 |
| pair_coupled | group_all_correct | 0.8208 | 0.7899 | 0.8485 | 614 |
| pair_coupled | orientation | 0.8581 | 0.8289 | 0.8844 | 592 |

## Pair-Coupled Minus Bucket Router

| metric | delta | ci95_low | ci95_high | sign wins | sign losses | sign p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| group_all_correct | 0.1091 | 0.0831 | 0.1352 | 73 | 6 | 1e-06 |
| orientation | 0.0 | 0.0 | 0.0 | 0 | 0 | 1.0 |

## Interpretation

Pair-coupled decoding changes discrete labels but not probability ordering, so orientation is expected to remain unchanged. Its value is in enforcing one positive and one negative decision inside paired groups, which directly targets group all-correct and row-level consistency.

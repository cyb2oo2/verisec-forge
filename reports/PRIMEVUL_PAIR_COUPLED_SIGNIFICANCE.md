# PrimeVul Pair-Coupled Significance Summary

This report packages the statistical support for the paired-diff mainline. It separates the strict same-split claim from the headline narrative comparison.

## Strict Same-Split Claim

Pair-coupled decoding is compared against the bucket-router baseline on the same held-out pair groups for each split seed.

| Metric | Mean Delta | 95% Bootstrap CI | Positive Splits |
| --- | ---: | ---: | ---: |
| balanced accuracy | `0.0348` | `[0.0329, 0.0368]` | `5/5` |
| group all-correct | `0.1114` | `[0.1046, 0.1199]` | `5/5` |

## Headline Comparison

| System | Mean BA | 95% Bootstrap CI | Values |
| --- | ---: | ---: | --- |
| diff-only three-seed | `0.8287` | `[0.8158, 0.8382]` | `[0.8158, 0.8382, 0.8321]` |
| pair-coupled five-split | `0.8572` | `[0.8523, 0.8616]` | `[0.8528, 0.8644, 0.8493, 0.8599, 0.8596]` |

Headline BA delta: `0.0285` (`0.8287` -> `0.8572`).

Caveat: the headline comparison uses related but not identical split protocols. The reviewer-facing strict test is the same-split pair-coupled versus bucket-router delta above.

## Paired Tests

- Row-level McNemar p-values across split seeds: `[1.6e-05, 2.1e-05, 1.6e-05, 3e-06, 0.001269]`
- Group all-correct sign-test p-values across split seeds: `[1e-06, 1e-06, 1e-06, 1e-06, 1e-06]`
- Orientation sign-test p-values across split seeds: `[1.0, 1.0, 1.0, 1.0, 1.0]`

## Interpretation

The strict same-split deltas are positive on all five split seeds, and the bootstrap intervals over split seeds stay above zero for both balanced accuracy and group all-correct. This supports pair-coupled decoding as the current statistically credible system layer. The headline `0.8287 -> 0.8572` comparison is useful for narrative compression, but it should be accompanied by the protocol caveat above.

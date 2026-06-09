# PrimeVul Targeted Nuisance Adaptation Pilot

This is a 375-pair pilot adaptation from the synthetic-supervised joint checkpoint. Both variants are evaluated at 512 tokens. Counterfactual rows use code-only identifier normalization and recompute each checkpoint's own base predictions.

## Main Task

| baseline | adapted | delta | repaired | introduced | McNemar p |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0.8174 | 0.8198 | +0.0024 | 14 | 12 | 0.845019 |

## Counterfactual Relation Success

| intervention | baseline | adapted | delta | repaired | introduced | McNemar p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `context_truncated` | 0.8175 | 0.8275 | +0.0100 | 14 | 10 | 0.541256 |
| `format_normalized` | 0.8400 | 0.8650 | +0.0250 | 21 | 11 | 0.110184 |
| `identifier_normalized` | 0.8100 | 0.8375 | +0.0275 | 21 | 10 | 0.0707555 |
| `metadata_removed` | 0.8475 | 0.8300 | -0.0175 | 10 | 17 | 0.247789 |
| `nonsecurity_padding` | 0.5750 | 0.8700 | +0.2950 | 136 | 18 | 1.32799e-23 |
| `side_order_swapped` | 0.7500 | 0.7275 | -0.0225 | 8 | 17 | 0.107752 |

## Interpretation

The pilot is successful only for targeted nuisance robustness, not as a new full-coverage accuracy result. Any regression on untargeted relations must remain visible when deciding whether to scale the adaptation.

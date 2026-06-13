# Independent Readout Confirmation

PR #8 is frozen as discovery. This study uses 180 new pair IDs, three unseen suffix templates, and training seeds 7 and 123.

## Per-Seed Endpoints

| readout | seed | canonical | macro suffix | swap | baseline | residual | both correct | visible | fallback |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `terminal` | 7 | 67.22% | 50.87% | 44.44% | 50.10% | -0.0565 | 37.22% | 85.56% | 0.00% |
| `terminal` | 123 | 70.00% | 51.08% | 51.11% | 49.35% | +0.0176 | 43.33% | 85.56% | 0.00% |
| `mean` | 7 | 66.67% | 81.39% | 45.56% | 49.57% | -0.0402 | 38.33% | 85.56% | 0.00% |
| `mean` | 123 | 67.78% | 82.47% | 46.67% | 48.92% | -0.0225 | 39.44% | 85.56% | 0.00% |
| `changed_hunk` | 7 | 66.67% | 100.00% | 47.78% | 49.93% | -0.0215 | 41.67% | 85.56% | 0.00% |
| `changed_hunk` | 123 | 65.56% | 100.00% | 47.78% | 49.93% | -0.0215 | 41.11% | 85.56% | 0.00% |

## Confirmatory Comparisons

| candidate | canonical delta | 95% CI | suffix delta | 95% CI | both seeds positive | confirmed |
| --- | ---: | --- | ---: | --- | --- | --- |
| `mean` | -0.0139 | [-0.0778, +0.0500] | +0.3095 | [+0.2348, +0.3799] | yes | no |
| `changed_hunk` | -0.0250 | [-0.1000, +0.0528] | +0.4903 | [+0.4448, +0.5357] | yes | no |

## Per-Source Pooled Deltas

| candidate | source | canonical delta | suffix delta | suffix 95% CI |
| --- | --- | ---: | ---: | --- |
| `mean` | `deltasecommits` | +0.0000 | +0.4496 | [+0.3450, +0.5543] |
| `mean` | `patcheval` | -0.0250 | +0.4091 | [+0.3182, +0.5000] |
| `mean` | `primevul` | -0.0167 | +0.1042 | [-0.0417, +0.2470] |
| `changed_hunk` | `deltasecommits` | -0.0667 | +0.5426 | [+0.4535, +0.6318] |
| `changed_hunk` | `patcheval` | -0.0333 | +0.5242 | [+0.4515, +0.5970] |
| `changed_hunk` | `primevul` | +0.0250 | +0.4167 | [+0.3423, +0.4940] |

Canonical non-inferiority uses all 180 pairs. The suffix endpoint uses only pairs where the intervention is visible after tokenization and truncation.

## Interpretation

- Neither candidate meets all preregistered confirmation checks.
- Side-swap equivariance remains a separate relational failure; endpoint robustness must not be presented as solving side order.
- Changed-hunk fallback and critical-hunk visibility are reported to expose implementation or truncation artifacts.

## Claim Boundary

This confirms readout-conditioned training behavior on new pair IDs and unseen suffixes. It does not isolate frozen-backbone pooling, and side-swap consistency is a separate endpoint.

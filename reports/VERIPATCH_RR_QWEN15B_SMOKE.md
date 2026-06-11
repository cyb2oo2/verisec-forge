# VeriPatch-RR Qwen 1.5B Smoke Evaluation

## Scope

This is the first frozen-instrument run on VeriPatch-RR v0.1. It evaluates the
existing PrimeVul-trained Qwen2.5-Coder-1.5B pairwise checkpoint without
additional adaptation.

- Runtime rows: `9,600`
- Prediction coverage: `100%`
- Protocol pass rate: `1.000`
- Inference time: `333.59` seconds
- Throughput: `28.78` rows/second
- Bootstrap: `2,000` pair-cluster resamples

The representative suite is the primary result. Balanced stress is reported
separately and is not mixed into the headline.

## Primary Results

| Metric | Representative | Balanced stress |
| --- | ---: | ---: |
| Base accuracy | 0.6533 | 0.6317 |
| End-to-end relation accuracy | 0.6958 | 0.6867 |
| Robust accuracy | 0.4883 | 0.4675 |
| Robust accuracy 95% CI | [0.4567, 0.5208] | [0.4358, 0.4992] |
| Side-swap equivariance | 0.4950 | 0.4983 |
| Clean no-truncation robust accuracy | 0.5259 | 0.5280 |

The central finding is that ordinary task accuracy substantially overstates
relational robustness. Side-swap behavior is near chance even though base
accuracy is above chance.

## Transformation Results

Representative-suite relation accuracy:

| Transformation | Relation accuracy |
| --- | ---: |
| Metadata removal | 0.8650 |
| Pre-diff neutral padding | 0.8017 |
| End neutral padding | 0.6217 |
| Canonical side swap | 0.4950 |

End padding does not truncate the critical hunk, so its low relation accuracy
is a direct nuisance-sensitivity result rather than a context-budget artifact.

## Context Pressure

| Metric | Representative | Balanced stress |
| --- | ---: | ---: |
| Overall decision-change rate | 0.2200 | 0.2589 |
| Evidence-visible decision-change rate | 0.0923 | 0.1100 |
| Evidence-truncated decision-change rate | 0.4704 | 0.4607 |
| Abstention rate | 0.0000 | 0.0000 |

The model never abstains. Decision changes rise roughly four to five times when
the critical evidence is truncated, validating the benchmark's decision to
separate context pressure from clean invariance.

## Cross-Source Results

Representative suite:

| Dataset | Base accuracy | Robust accuracy | Side-swap equivariance |
| --- | ---: | ---: | ---: |
| PrimeVul | 0.7900 | 0.6275 | 0.6600 |
| PatchEval | 0.6800 | 0.5625 | 0.6900 |
| DeltaSecommits | 0.4900 | 0.2750 | 0.1350 |

The DeltaSecommits collapse is the dominant failure. It indicates source-domain
and orientation mismatch rather than a universal secure-patch reasoner.
Balanced stress preserves the same ordering, so this is not explained only by
the representative sample.

## Claim Boundary

This is a smoke-model result, not a cross-model conclusion. It establishes that
VeriPatch-RR can expose relational and source-specific failures hidden by base
accuracy. The next experiment should compare at least two additional model
families under the frozen pair IDs, templates, runtime schema, and metrics.

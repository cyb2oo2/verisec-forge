# Non-Oracle Source Router

This report replaces explicit source-label routing with a lightweight metadata-schema router.

## Router Protocol

- Forbidden fields: `source_dataset, id, pair_key`
- Limitation: This is a non-oracle source router because it does not consume explicit source labels, but it is still a metadata-schema router. It should be treated as a routing sanity check, not a deployment-grade semantic source classifier.

## Routing Accuracy

- Row accuracy: `1.0`
- Pair-group accuracy: `1.0`

| True Source | Rows | Correct | Accuracy |
| --- | ---: | ---: | ---: |
| `DeltaSecommits` | `654` | `654` | `1.0` |
| `PatchEval` | `538` | `538` | `1.0` |
| `PrimeVul-time` | `1562` | `1562` | `1.0` |

## System Results

| System | BA | Recall | Specificity | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `single matched-mixed checkpoint` | `0.8591` | `0.854` | `0.8642` | `0.8584` | `0.8482` | `0.86` |
| `oracle source-routed experts` | `0.8664` | `0.8627` | `0.87` | `0.8659` | `0.857` | `0.8674` |
| `non-oracle metadata-schema router` | `0.8664` | `0.8627` | `0.87` | `0.8659` | `0.857` | `0.8674` |

## Deltas

- Automatic minus single BA: `0.0073`
- Automatic minus single group all-correct: `0.0088`
- Automatic minus oracle BA: `0.0`
- Automatic minus oracle group all-correct: `0.0`

## Interpretation

The metadata-schema router exactly matches the oracle source assignment on this three-source benchmark. The result supports source-aware routing as a system layer, but the next step is a content-based router that avoids dataset-schema fingerprints.

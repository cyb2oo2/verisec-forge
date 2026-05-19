# Three-Source Adapter Mixture

This report extends source-aware routing to PrimeVul-time, DeltaSecommits, and PatchEval.

## Results

| System | BA | Recall | Specificity | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `single matched-mixed checkpoint` | `0.8591` | `0.854` | `0.8642` | `0.8584` | `0.8482` | `0.86` |
| `available source-routed adapters` | `0.8664` | `0.8627` | `0.87` | `0.8659` | `0.857` | `0.8674` |

## Delta

- Routed minus single BA: `0.0073`
- Routed minus single F1: `0.0075`
- Routed minus single group all-correct: `0.0088`
- Routed minus single orientation: `0.0074`

## PatchEval Adapter

- Available: `True`
- Adapter: `patcheval expert`
- Next protocol: Run multi-seed PatchEval adapters and cross-evaluate the PatchEval expert on PrimeVul/Delta to quantify specialization tradeoffs.

## Interpretation

The three-source source-routed adapter mixture improves over a single matched-mixed checkpoint. With the PatchEval expert available, the mixture now covers the hardest cross-language source rather than relying on a fallback.

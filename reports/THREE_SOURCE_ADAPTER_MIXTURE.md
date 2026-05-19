# Three-Source Adapter Mixture

This report extends source-aware routing to PrimeVul-time, DeltaSecommits, and PatchEval.

## Results

| System | BA | Recall | Specificity | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `single matched-mixed checkpoint` | `0.8591` | `0.854` | `0.8642` | `0.8584` | `0.8482` | `0.86` |
| `available source-routed adapters` | `0.8624` | `0.8584` | `0.8664` | `0.8618` | `0.8541` | `0.8622` |

## Delta

- Routed minus single BA: `0.0033`
- Routed minus single F1: `0.0034`
- Routed minus single group all-correct: `0.0059`
- Routed minus single orientation: `0.0022`

## Missing Adapter

- Source: `PatchEval`
- Reason: No completed PatchEval-specific 1.5B LoRA adapter yet; attempted full run was stopped because observed step time projected to multi-hour training.
- Next protocol: Run PatchEval-specific adapter on a faster Linux/CUDA training path or a controlled smaller-model smoke before adding it as a routed expert.

## Interpretation

The three-source mixture still improves over a single matched-mixed checkpoint using only the available PrimeVul and Delta source experts. The next adapter experiment should target PatchEval specifically, because it is now the unfilled expert slot and the hardest cross-language source.

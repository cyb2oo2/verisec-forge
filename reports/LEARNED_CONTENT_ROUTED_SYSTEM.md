# Learned Content-Routed System

This report turns the learned diff-body source router into an end-to-end routed-system evaluation.

## Protocol

- Router: `character n-gram naive bayes over diff-body-only text`
- Routing accuracy: `0.9063`
- Available cross predictions: `DeltaSecommits->PatchEval, DeltaSecommits->PrimeVul-time, PrimeVul-time->PatchEval`
- Missing cross-prediction fallbacks: `{'PrimeVul-time->DeltaSecommits': 228, 'PatchEval->PrimeVul-time': 2}`

## System Results

| System | BA | Recall | Specificity | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `single matched-mixed checkpoint` | `0.8591` | `0.854` | `0.8642` | `0.8584` | `0.8482` | `0.86` |
| `oracle source-routed experts` | `0.8664` | `0.8627` | `0.87` | `0.8659` | `0.857` | `0.8674` |
| `learned diff-body router with available cross-prediction fallback` | `0.8664` | `0.8635` | `0.8693` | `0.866` | `0.8563` | `0.8681` |

## Deltas

- Learned minus single BA: `0.0073`
- Learned minus single group all-correct: `0.0081`
- Learned minus oracle BA: `0.0`
- Learned minus oracle group all-correct: `-0.0007`

## Routing Confusion

```json
{
  "PrimeVul-time": {
    "PrimeVul-time": 1322,
    "DeltaSecommits": 228,
    "PatchEval": 12
  },
  "DeltaSecommits": {
    "DeltaSecommits": 638,
    "PrimeVul-time": 10,
    "PatchEval": 6
  },
  "PatchEval": {
    "PatchEval": 536,
    "PrimeVul-time": 2
  }
}
```

## Interpretation

The learned diff-body router can now be evaluated as a routed system rather than only as a source classifier. The current result should still be read with its fallback policy: several cross-expert prediction files are not yet materialized, so misroutes without cross predictions use the matched-mixed fallback instead of an unobserved expert output.

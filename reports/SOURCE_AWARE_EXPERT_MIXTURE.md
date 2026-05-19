# Source-Aware Expert Mixture

This report compares a single matched mixed-source checkpoint against a lightweight source-routed mixture of existing source-specific experts.

## Results

| System | BA | Recall | Specificity | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `single matched-mixed checkpoint` | `0.8714` | `0.8664` | `0.8764` | `0.8707` | `0.8603` | `0.8722` |
| `source-routed expert mixture` | `0.8755` | `0.8718` | `0.8791` | `0.875` | `0.8676` | `0.875` |

## Delta

- Routed minus single BA: `0.0041`
- Routed minus single F1: `0.0043`
- Routed minus single group all-correct: `0.0073`
- Routed minus single orientation: `0.0028`

## Interpretation

A source-routed expert mixture improves the aggregate pair-coupled result over the single matched-mixed checkpoint. This supports source-aware adaptation/mixture as the next training direction, while keeping the claim lightweight because the route uses known dataset source.

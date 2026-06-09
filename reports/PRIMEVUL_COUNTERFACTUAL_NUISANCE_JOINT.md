# Counterfactual Shortcut Evaluation

This report measures whether the 1.5B paired-diff detector changes under controlled nuisance interventions. Invariant interventions should preserve the prediction, side-order swap should flip it equivariantly, and context truncation should reduce confidence or trigger abstention.

## Results

| Intervention | Expected relation | Unexpected change | 95% CI | Mean absolute probability shift | 0->1 / 1->0 flips | Base / intervention expected-label accuracy |
| --- | --- | ---: | --- | ---: | --- | --- |
| `context_truncated` | `abstention_sensitivity` | `0.1725` | `[0.1386, 0.2126]` | `0.2134` | `42 / 42` | `n/a` |
| `format_normalized` | `invariant` | `0.1350` | `[0.1050, 0.1720]` | `0.1463` | `32 / 22` | `0.7900 / 0.7700` |
| `identifier_normalized` | `invariant` | `0.1625` | `[0.1296, 0.2018]` | `0.1654` | `32 / 33` | `0.7900 / 0.7625` |
| `metadata_removed` | `invariant` | `0.1700` | `[0.1364, 0.2099]` | `0.1582` | `52 / 16` | `0.7900 / 0.7850` |
| `nonsecurity_padding` | `invariant` | `0.1300` | `[0.1005, 0.1665]` | `0.1534` | `38 / 14` | `0.7900 / 0.7500` |
| `side_order_swapped` | `equivariant_flip` | `0.2725` | `[0.2312, 0.3181]` | `0.6872` | `145 / 146` | `0.7900 / 0.7925` |

## Interpretation

- A high invariant-intervention change rate is direct evidence that predictions depend on nuisance presentation features.
- Side-order equivariance below `1.0` shows that independently scored candidate-vs-counterpart prompts do not implement a fully symmetric pair decision.
- Context truncation is evaluated as confidence/abstention sensitivity, not label invariance.
- These results diagnose the retained 1.5B diff-only detector and motivate the learned joint model with counterfactual consistency training.

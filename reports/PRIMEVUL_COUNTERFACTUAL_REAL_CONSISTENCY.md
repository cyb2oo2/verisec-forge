# Counterfactual Shortcut Evaluation

This report measures whether the 1.5B paired-diff detector changes under controlled nuisance interventions. Invariant interventions should preserve the prediction, side-order swap should flip it equivariantly, and context truncation should reduce confidence or trigger abstention.

## Results

| Intervention | Expected relation | Unexpected change | 95% CI | Mean absolute probability shift | 0->1 / 1->0 flips | Base / intervention expected-label accuracy |
| --- | --- | ---: | --- | ---: | --- | --- |
| `context_truncated` | `abstention_sensitivity` | `0.3575` | `[0.3121, 0.4056]` | `0.3361` | `43 / 108` | `n/a` |
| `format_normalized` | `invariant` | `0.2225` | `[0.1845, 0.2658]` | `0.2116` | `68 / 21` | `0.7900 / 0.7175` |
| `identifier_normalized` | `invariant` | `0.2650` | `[0.2241, 0.3103]` | `0.2649` | `21 / 85` | `0.7900 / 0.6050` |
| `metadata_removed` | `invariant` | `0.1150` | `[0.0873, 0.1500]` | `0.1564` | `34 / 12` | `0.7900 / 0.7650` |
| `nonsecurity_padding` | `invariant` | `0.5750` | `[0.5261, 0.6225]` | `0.4240` | `227 / 3` | `0.7900 / 0.5350` |
| `side_order_swapped` | `equivariant_flip` | `0.3125` | `[0.2690, 0.3595]` | `0.6384` | `137 / 138` | `0.7900 / 0.7875` |

## Interpretation

- A high invariant-intervention change rate is direct evidence that predictions depend on nuisance presentation features.
- Side-order equivariance below `1.0` shows that independently scored candidate-vs-counterpart prompts do not implement a fully symmetric pair decision.
- Context truncation is evaluated as confidence/abstention sensitivity, not label invariance.
- These results diagnose the retained 1.5B diff-only detector and motivate the learned joint model with counterfactual consistency training.

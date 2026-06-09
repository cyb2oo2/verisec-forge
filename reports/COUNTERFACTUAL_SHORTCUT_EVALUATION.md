# Counterfactual Shortcut Evaluation

This report measures whether the 1.5B paired-diff detector changes under controlled nuisance interventions. Invariant interventions should preserve the prediction, side-order swap should flip it equivariantly, and context truncation should reduce confidence or trigger abstention.

## Results

| Intervention | Expected relation | Unexpected change | 95% CI | Mean absolute probability shift | 0->1 / 1->0 flips | Base / intervention expected-label accuracy |
| --- | --- | ---: | --- | ---: | --- | --- |
| `context_truncated` | `abstention_sensitivity` | `0.2475` | `[0.2077, 0.2921]` | `0.3714` | `68 / 99` | `n/a` |
| `format_normalized` | `invariant` | `0.4500` | `[0.4020, 0.4990]` | `0.4093` | `160 / 20` | `0.7275 / 0.6125` |
| `identifier_normalized` | `invariant` | `0.3075` | `[0.2643, 0.3544]` | `0.3234` | `33 / 90` | `0.7275 / 0.5850` |
| `metadata_removed` | `invariant` | `0.3175` | `[0.2738, 0.3647]` | `0.3217` | `84 / 43` | `0.7275 / 0.6700` |
| `nonsecurity_padding` | `invariant` | `0.6075` | `[0.5588, 0.6541]` | `0.4990` | `239 / 4` | `0.7275 / 0.5250` |
| `side_order_swapped` | `equivariant_flip` | `0.2650` | `[0.2241, 0.3103]` | `0.6564` | `175 / 119` | `0.7275 / 0.8225` |

## Interpretation

- A high invariant-intervention change rate is direct evidence that predictions depend on nuisance presentation features.
- Side-order equivariance below `1.0` shows that independently scored candidate-vs-counterpart prompts do not implement a fully symmetric pair decision.
- Context truncation is evaluated as confidence/abstention sensitivity, not label invariance.
- These results diagnose the retained 1.5B diff-only detector and motivate the learned joint model with counterfactual consistency training.

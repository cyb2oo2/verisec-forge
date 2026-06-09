# Counterfactual Shortcut Evaluation

This report measures whether the 1.5B paired-diff detector changes under controlled nuisance interventions. Invariant interventions should preserve the prediction, side-order swap should flip it equivariantly, and context truncation should reduce confidence or trigger abstention.

## Results

| Intervention | Expected relation | Unexpected change | 95% CI | Mean absolute probability shift | 0->1 / 1->0 flips | Base / intervention expected-label accuracy |
| --- | --- | ---: | --- | ---: | --- | --- |
| `context_truncated` | `abstention_sensitivity` | `0.1550` | `[0.1228, 0.1937]` | `0.1966` | `33 / 47` | `n/a` |
| `format_normalized` | `invariant` | `0.1700` | `[0.1364, 0.2099]` | `0.1665` | `49 / 19` | `0.8225 / 0.7725` |
| `identifier_normalized` | `invariant` | `0.2125` | `[0.1752, 0.2552]` | `0.2490` | `20 / 65` | `0.8225 / 0.6950` |
| `metadata_removed` | `invariant` | `0.1500` | `[0.1183, 0.1883]` | `0.1548` | `55 / 5` | `0.8225 / 0.7875` |
| `nonsecurity_padding` | `invariant` | `0.4650` | `[0.4167, 0.5140]` | `0.3830` | `186 / 0` | `0.8225 / 0.5725` |
| `side_order_swapped` | `equivariant_flip` | `0.2250` | `[0.1868, 0.2684]` | `0.7251` | `155 / 155` | `0.8225 / 0.8225` |

## Interpretation

- A high invariant-intervention change rate is direct evidence that predictions depend on nuisance presentation features.
- Side-order equivariance below `1.0` shows that independently scored candidate-vs-counterpart prompts do not implement a fully symmetric pair decision.
- Context truncation is evaluated as confidence/abstention sensitivity, not label invariance.
- These results diagnose the retained 1.5B diff-only detector and motivate the learned joint model with counterfactual consistency training.

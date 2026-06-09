# Counterfactual Shortcut Evaluation

This report measures whether the 1.5B paired-diff detector changes under controlled nuisance interventions. Invariant interventions should preserve the prediction, side-order swap should flip it equivariantly, and context truncation should reduce confidence or trigger abstention.

## Results

| Intervention | Expected relation | Unexpected change | 95% CI | Mean absolute probability shift | 0->1 / 1->0 flips | Base / intervention expected-label accuracy |
| --- | --- | ---: | --- | ---: | --- | --- |
| `context_truncated` | `abstention_sensitivity` | `0.1825` | `[0.1477, 0.2233]` | `0.2112` | `34 / 52` | `n/a` |
| `format_normalized` | `invariant` | `0.1600` | `[0.1273, 0.1991]` | `0.1602` | `40 / 24` | `0.8000 / 0.7650` |
| `identifier_normalized` | `invariant` | `0.1900` | `[0.1546, 0.2313]` | `0.1718` | `40 / 36` | `0.8000 / 0.7550` |
| `metadata_removed` | `invariant` | `0.1525` | `[0.1206, 0.1910]` | `0.1595` | `47 / 14` | `0.8000 / 0.7825` |
| `nonsecurity_padding` | `invariant` | `0.4250` | `[0.3775, 0.4739]` | `0.3579` | `167 / 3` | `0.8000 / 0.5700` |
| `side_order_swapped` | `equivariant_flip` | `0.2500` | `[0.2101, 0.2947]` | `0.6980` | `150 / 150` | `0.8000 / 0.8000` |

## Interpretation

- A high invariant-intervention change rate is direct evidence that predictions depend on nuisance presentation features.
- Side-order equivariance below `1.0` shows that independently scored candidate-vs-counterpart prompts do not implement a fully symmetric pair decision.
- Context truncation is evaluated as confidence/abstention sensitivity, not label invariance.
- These results diagnose the retained 1.5B diff-only detector and motivate the learned joint model with counterfactual consistency training.

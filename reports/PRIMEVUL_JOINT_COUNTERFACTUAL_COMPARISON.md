# PrimeVul Joint Counterfactual Comparison

Both checkpoints recompute their own 400 base predictions and use the same 768-token inference cap.

| Variant | Base accuracy | Mean invariant change | Side-order violation | Context-truncation change |
| --- | ---: | ---: | ---: | ---: |
| Synthetic-supervised | `0.8225` | `0.2494` | `0.2250` | `0.1550` |
| Real + consistency | `0.7900` | `0.2944` | `0.3125` | `0.3575` |

Lower change/violation rates are better; higher base accuracy is better.

The synthetic-supervised checkpoint is stronger overall. Real + consistency improves metadata-removal invariance, but it does not yet provide a better accuracy-robustness tradeoff.

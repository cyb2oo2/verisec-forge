# Learned Content-Routed System Statistics

This report estimates uncertainty for the learned diff-body routed system against the single matched-mixed baseline and oracle source-routed experts.

## Bootstrap 95% Confidence Intervals

| system | metric | observed | ci95_low | ci95_high | units |
| --- | --- | ---: | ---: | ---: | ---: |
| `single matched-mixed checkpoint` | `balanced_accuracy` | `0.8591` | `0.8415` | `0.8763` | `1357` |
| `single matched-mixed checkpoint` | `group_all_correct_rate` | `0.8482` | `0.829` | `0.8674` | `1357` |
| `single matched-mixed checkpoint` | `orientation_accuracy` | `0.86` | `0.8416` | `0.8784` | `1357` |
| `oracle source-routed experts` | `balanced_accuracy` | `0.8664` | `0.8483` | `0.8846` | `1357` |
| `oracle source-routed experts` | `group_all_correct_rate` | `0.857` | `0.8379` | `0.8762` | `1357` |
| `oracle source-routed experts` | `orientation_accuracy` | `0.8674` | `0.8482` | `0.8858` | `1357` |
| `learned diff-body router with full cross-prediction matrix` | `balanced_accuracy` | `0.8664` | `0.8483` | `0.8844` | `1357` |
| `learned diff-body router with full cross-prediction matrix` | `group_all_correct_rate` | `0.8548` | `0.8349` | `0.874` | `1357` |
| `learned diff-body router with full cross-prediction matrix` | `orientation_accuracy` | `0.8681` | `0.8497` | `0.8865` | `1357` |

## Learned Minus Comparators

| comparator | metric | delta | ci95_low | ci95_high | paired test | p-value |
| --- | --- | ---: | ---: | ---: | --- | ---: |
| `single matched-mixed checkpoint` | `balanced_accuracy` | `0.0073` | `0.0` | `0.0145` | `exact_mcnemar_binomial` | `0.024461` |
| `single matched-mixed checkpoint` | `group_all_correct_rate` | `0.0066` | `-0.0015` | `0.0147` | `exact_group_sign_test` | `0.175465` |
| `single matched-mixed checkpoint` | `orientation_accuracy` | `0.0081` | `0.0` | `0.0162` | `exact_group_sign_test` | `0.070756` |
| `oracle source-routed experts` | `balanced_accuracy` | `0.0` | `-0.0022` | `0.0022` | `exact_mcnemar_binomial` | `1.0` |
| `oracle source-routed experts` | `group_all_correct_rate` | `-0.0022` | `-0.0052` | `0.0007` | `exact_group_sign_test` | `0.375` |
| `oracle source-routed experts` | `orientation_accuracy` | `0.0007` | `-0.0015` | `0.0029` | `exact_group_sign_test` | `1.0` |

## Interpretation

The learned routed system improves over the single matched-mixed baseline at the point estimate, but the bootstrap interval should be used as the reviewer-facing claim boundary. Against oracle source routing, the learned system matches row-level balanced accuracy while remaining slightly below oracle group all-correct.

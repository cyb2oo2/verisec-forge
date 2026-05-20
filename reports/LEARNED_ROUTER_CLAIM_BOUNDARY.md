# Learned Router Claim Boundary

This reviewer-facing summary consolidates the statistical, feature-ablation, and leave-one-source evidence for learned source/expert routing.

## Main Claim

Learned diff-body routing provides a small row-level system gain in a closed-world three-source setting, but group consistency and unseen-source routing remain bounded claims.

## Boundary Table

| Check | Evidence | Reviewer-safe interpretation |
| --- | --- | --- |
| Closed-world statistical support | BA delta `0.0073`, CI `[0, 0.0145]`, McNemar p `0.024461` | Small row-level gain over single matched-mixed baseline. |
| Group consistency | group all-correct delta `0.0066`, CI `[-0.0015, 0.0147]` | Not statistically reliable; do not claim broad pair consistency gain. |
| Feature ablation | char BA `0.8664`, token BA `0.8627`, diff-line BA `0.8649` | System benefit is not exclusive to one char n-gram view, but char routing remains strongest. |
| Leave-one-source stress | held-out routed-minus-oracle BA range `[-0.025, -0.0077]` | Closed-world adapter selection, not unseen-source expert discovery. |

## Feature View Summary

| Feature mode | Routing row accuracy | Routed BA | Delta vs single BA |
| --- | ---: | ---: | ---: |
| `char_3_5` | `0.9063` | `0.8664` | `0.0073` |
| `token_1_2` | `0.7106` | `0.8627` | `0.0036` |
| `diff_line_markers` | `0.7778` | `0.8649` | `0.0058` |

## Leave-One-Source Summary

| Held-out source | Routed minus oracle BA |
| --- | ---: |
| `PrimeVul-time` | `-0.025` |
| `DeltaSecommits` | `-0.0077` |
| `PatchEval` | `-0.0242` |

## Conclusion

The safest claim is closed-world source-aware expert selection. The row-level BA gain over a single matched-mixed checkpoint is statistically positive at the point estimate, weaker feature views preserve some system benefit, and leave-one-source stress prevents overclaiming unseen-source expert discovery.

# Learned Content Router Feature Ablation

This report compares diff-body-only source/expert routing across lightweight feature views.

## Feature Results

| Feature mode | Route row acc | Route pair acc | Routed BA | Routed group all-correct | Delta vs single BA | Delta vs oracle BA | Fallback rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `char_3_5` | `0.9063` | `0.9057` | `0.8664` | `0.8548` | `0.0073` | `0.0` | `0` |
| `token_1_2` | `0.7106` | `0.7089` | `0.8627` | `0.8452` | `0.0036` | `-0.0037` | `0` |
| `diff_line_markers` | `0.7778` | `0.773` | `0.8649` | `0.8497` | `0.0058` | `-0.0015` | `0` |

## Per-Source Routing Accuracy

| Feature mode | PrimeVul-time | DeltaSecommits | PatchEval |
| --- | ---: | ---: | ---: |
| `char_3_5` | `0.8464` | `0.9755` | `0.9963` |
| `token_1_2` | `0.6543` | `0.6162` | `0.9888` |
| `diff_line_markers` | `0.71` | `0.7752` | `0.9777` |

## Interpretation

Feature ablation is a robustness check, not a new headline metric. If token or diff-line features remain competitive, the router claim is less dependent on a single character-fingerprint representation; if they collapse, the claim should stay narrow.

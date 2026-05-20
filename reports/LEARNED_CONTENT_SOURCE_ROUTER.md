# Learned Content Source Router

This report trains a lightweight character n-gram Naive Bayes router for source/expert selection.

## Protocol

- Model: `character n-gram multinomial naive bayes`
- Max features: `50000`
- Forbidden row fields: `source_dataset, id, pair_key, programming_language, file_extension, file_path, patch_url`

## Routing Results

| Router | Row Accuracy | Pair Accuracy | PrimeVul Acc | Delta Acc | PatchEval Acc |
| --- | ---: | ---: | ---: | ---: | ---: |
| `heuristic_surface` | `1.0` | `1.0` | `1.0` | `1.0` | `1.0` |
| `heuristic_diff_body` | `0.4466` | `0.4436` | `0.4814` | `0.1315` | `0.7286` |
| `learned_surface` | `0.911` | `0.9108` | `0.847` | `0.9908` | `1.0` |
| `learned_diff_body` | `0.9063` | `0.9057` | `0.8464` | `0.9755` | `0.9963` |

## Model Stats

- Surface vocab size: `50000`
- Diff-body vocab size: `50000`

## Interpretation

The learned character n-gram router establishes a dependency-free content-routing baseline. Surface routing tests whether visible prompt content can select experts; diff-body routing is the stricter check for code-diff-only expert selection.

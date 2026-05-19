# PatchEval Adapter Multi-Seed Evaluation

This report summarizes three PatchEval source-specific Qwen2.5-Coder-1.5B LoRA adapter runs.

## Per-Seed Results

| Seed | Default BA | Pair-Coupled BA | Delta BA | Pair F1 | Group All-Correct | Orientation | Best Threshold BA |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `42` | `0.8011` | `0.829` | `0.0279` | `0.8284` | `0.8141` | `0.8364` | `0.8011` |
| `7` | `0.7993` | `0.8197` | `0.0204` | `0.8187` | `0.8104` | `0.8141` | `0.7993` |
| `99` | `0.7546` | `0.803` | `0.0484` | `0.8008` | `0.7881` | `0.8067` | `0.7788` |

## Multi-Seed Summary

| Metric | Mean | Min | Max | Range | Std |
| --- | ---: | ---: | ---: | ---: | ---: |
| Default BA | `0.785` | `0.7546` | `0.8011` | `0.0465` | `0.0215` |
| Pair-coupled BA | `0.8172` | `0.803` | `0.829` | `0.026` | `0.0108` |
| Pair-coupled F1 | `0.816` | `0.8008` | `0.8284` | `0.0276` | `0.0114` |
| Group all-correct | `0.8042` | `0.7881` | `0.8141` | `0.026` | `0.0115` |
| Orientation | `0.8191` | `0.8067` | `0.8364` | `0.0297` | `0.0126` |
| Pair-coupled minus default BA | `0.0322` | `0.0204` | `0.0484` | `0.028` | `0.0118` |
| Pair-coupled minus default group all-correct | `0.1152` | `0.1078` | `0.1264` | `0.0186` | `0.008` |
| Best threshold BA | `0.7931` | `0.7788` | `0.8011` | `0.0223` | `0.0101` |

## Interpretation

PatchEval source-specific adaptation is beneficial but seed-sensitive. Across three seeds, pair-coupled decoding consistently improves over the default threshold and keeps the cross-language PatchEval adapter above the zero-shot matched-mixed baseline.

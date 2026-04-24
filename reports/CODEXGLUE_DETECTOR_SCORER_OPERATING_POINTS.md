# CodeXGLUE Detector + Evidence Scorer Operating Points

These operating points summarize the current `CodeXGLUE` two-stage system:

1. a discriminative `presence-only detector` (`Qwen2.5-Coder-1.5B-Instruct`, LoRA sequence classification)
2. a narrow non-generative `evidence scorer` that decides whether a detector-positive alert is supported

The numbers below are measured on [secure_code_codexglue_holdout_eval_balanced_2000.jsonl](D:/code/start/data/processed/secure_code_codexglue_holdout_eval_balanced_2000.jsonl).

## Single-Threshold Readout

This table fixes the scorer threshold at `0.5` and sweeps only the detector threshold.

| Detector Threshold | Scorer Threshold | Detector Positive Rate | Scorer Positive Rate | Unsupported Positive Share | Presence Accuracy | Vulnerable Recall | Safe Specificity | Precision | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `0.2` | `0.5` | 0.9370 | 0.4185 | 0.4456 | 0.5455 | 0.4640 | 0.6270 | 0.5544 | 0.5052 |
| `0.5` | `0.5` | 0.4165 | 0.2340 | 0.3526 | 0.5690 | 0.3030 | 0.8350 | 0.6474 | 0.4128 |
| `0.8` | `0.5` | 0.1200 | 0.0980 | 0.1990 | 0.5590 | 0.1570 | 0.9610 | 0.8010 | 0.2625 |

## Two-Dimensional Threshold Grid

This table sweeps both the detector threshold and the scorer threshold.

| Detector Threshold | Scorer Threshold | Presence Accuracy | Vulnerable Recall | Safe Specificity | Precision | F1 | Unsupported Positive Share |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `0.2` | `0.2` | 0.5380 | 0.8730 | 0.2030 | 0.5228 | 0.6539 | 0.4772 |
| `0.2` | `0.5` | 0.5455 | 0.4640 | 0.6270 | 0.5544 | 0.5052 | 0.4456 |
| `0.2` | `0.8` | 0.5435 | 0.1420 | 0.9450 | 0.7208 | 0.2373 | 0.2792 |
| `0.5` | `0.2` | 0.6055 | 0.4800 | 0.7310 | 0.6409 | 0.5489 | 0.3591 |
| `0.5` | `0.5` | 0.5690 | 0.3030 | 0.8350 | 0.6474 | 0.4128 | 0.3526 |
| `0.5` | `0.8` | 0.5425 | 0.1270 | 0.9580 | 0.7515 | 0.2173 | 0.2485 |
| `0.8` | `0.2` | 0.5665 | 0.1770 | 0.9560 | 0.8009 | 0.2899 | 0.1991 |
| `0.8` | `0.5` | 0.5590 | 0.1570 | 0.9610 | 0.8010 | 0.2625 | 0.1990 |
| `0.8` | `0.8` | 0.5440 | 0.1090 | 0.9790 | 0.8385 | 0.1929 | 0.1615 |

## Readout

- The best accuracy point is `detector=0.5, scorer=0.2` with `presence_accuracy = 0.6055`.
- The best F1 and recall point is `detector=0.2, scorer=0.2`, but it has weak specificity (`0.2030`) and a high unsupported-positive share (`0.4772`).
- The most conservative point is `detector=0.8, scorer=0.8`, with `safe_specificity = 0.9790` and `precision = 0.8385`, but recall collapses to `0.1090`.
- Compared with the full-balanced detector-only holdout result (`presence_accuracy = 0.6135`, `f1 = 0.6741` at its best F1 threshold), the scorer does not yet improve balanced end-to-end detection.

## Failure Breakdown At Best Accuracy Point

For the best balanced point (`detector=0.5`, `scorer=0.2`), the failure split is:

| Bucket | Count |
| --- | ---: |
| true_positive_supported | 480 |
| true_negative_detector_reject | 697 |
| true_negative_scorer_reject | 34 |
| false_positive_supported_safe | 269 |
| false_negative_detector_miss | 470 |
| false_negative_scorer_reject | 50 |

This makes the next training target clearer:

- `90.38%` of false negatives are detector misses, not scorer rejections.
- `9.62%` of false negatives are introduced by the scorer gate.
- `95.35%` of true negatives are already rejected by the detector before the scorer is involved.
- The main remaining `CodeXGLUE` bottleneck is therefore detector discrimination, while the scorer mainly controls how conservative the positive path should be.

## Practical Interpretation

- On `CodeXGLUE`, the non-generative scorer is useful as a policy layer, but it is not yet a detector improvement.
- The scorer can sharpen precision and specificity when we want conservative confirmation.
- The contrast with `PrimeVul` is now clearer:
  - on `PrimeVul`, the scorer turns a good detector into a much stronger two-stage system
  - on `CodeXGLUE`, the scorer mainly trades recall for stronger confirmation
- The current evidence suggests that second-stage scoring helps most when the benchmark and labels make "supported vs unsupported positive" a meaningful task in its own right.

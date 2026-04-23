# PrimeVul Detector + Evidence Confirmer Operating Points

These operating points summarize the current `PrimeVul` two-stage system:

1. a `presence-only detector` (`Qwen2.5-Coder-1.5B-Instruct`, LoRA sequence classification)
2. a narrow `evidence confirmer` trained only on detector-positive traffic

All results below are measured on [secure_code_primevul_holdout_eval_balanced_2000.jsonl](D:/code/start/data/processed/secure_code_primevul_holdout_eval_balanced_2000.jsonl).

| Detector Threshold | Detector Positive Rate | Confirmer Positive Rate | Unsupported Positive Share | Avg Evidence Items / Positive | Presence Accuracy | Vulnerable Recall | Safe Specificity | Precision | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `0.2` | 0.5252 | 0.2122 | 0.0026 | 1.5383 | 0.6876 | 0.3998 | 0.9754 | 0.9420 | 0.5613 |
| `0.5` | 0.5185 | 0.2094 | 0.0027 | 1.5294 | 0.6892 | 0.3987 | 0.9798 | 0.9519 | 0.5620 |
| `0.8` | 0.5078 | 0.2055 | 0.0027 | 1.5259 | 0.6909 | 0.3964 | 0.9854 | 0.9646 | 0.5619 |

## Readout

- The operating-point family is much flatter than the earlier `CodeXGLUE detector + auditor` system.
- Changing the detector threshold shifts the incoming positive traffic only slightly (`0.5252 -> 0.5078`), and the confirmer then compresses all three settings into a very similar final positive path.
- This is a useful systems result: once the confirmer is in place, the dominant decision boundary is no longer the detector threshold alone.
- `unsupported_positive_share` is now very low across all three settings (`~0.0026-0.0027`), which is the first evidence in the repo that a second stage can produce evidence-backed positives without collapsing to zero recall.
- The tradeoff is now modest and interpretable:
  - lower thresholds retain slightly more recall
  - higher thresholds buy slightly better specificity and precision
  - all three operating points stay close in F1 (`0.5613-0.5620`)

## Practical Interpretation

- `0.2` is the most recall-friendly setting, but only marginally so.
- `0.5` is the cleanest default balanced setting.
- `0.8` is the most conservative trustworthy setting, with the highest specificity and precision.

The main conclusion is that `PrimeVul detector + evidence confirmer` has crossed an important line: it is no longer a brittle proof-of-concept. It is now a stable two-stage operating-point family, although the confirmer remains the main determinant of the final positive path.

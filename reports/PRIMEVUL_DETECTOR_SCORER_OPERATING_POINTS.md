# PrimeVul Detector + Support Scorer Operating Points

These operating points summarize the current `PrimeVul` two-stage system:

1. a high-recall `presence-only detector` (`Qwen2.5-Coder-1.5B-Instruct`, LoRA sequence classification)
2. a narrow non-generative `support scorer` that only decides whether a detector-positive alert is supported

All results below are measured on [secure_code_primevul_holdout_eval_balanced_2000.jsonl](D:/code/start/data/processed/secure_code_primevul_holdout_eval_balanced_2000.jsonl).

| Detector Threshold | Detector Positive Rate | Scorer Positive Rate | Acceptance On Detector Positives | Presence Accuracy | Vulnerable Recall | Safe Specificity | Precision | F1 | Delta F1 vs Detector |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `0.2` | 0.5252 | 0.4899 | 0.9328 | 0.9272 | 0.9171 | 0.9373 | 0.9360 | 0.9265 | -0.0249 |
| `0.5` | 0.5185 | 0.4899 | 0.9449 | 0.9272 | 0.9171 | 0.9373 | 0.9360 | 0.9265 | -0.0268 |
| `0.8` | 0.5078 | 0.4810 | 0.9471 | 0.9250 | 0.9059 | 0.9440 | 0.9418 | 0.9235 | -0.0254 |

## Readout

- The detector-only / probability pass-through control is stronger than the current support scorer: `presence_accuracy = 0.9524`, `vulnerable_recall = 0.9709`, `safe_specificity = 0.9339`, `precision = 0.9363`, and `f1 = 0.9533`.
- The support scorer does filter some detector-positive alerts, but every measured operating point is worse than detector-only on F1.
- `threshold = 0.5` remains the clearest default for reporting because it matches the detector-positive traffic used to train and evaluate the scorer.
- `threshold = 0.2` only adds a small number of extra detector-positive rows without scorer predictions in this artifact, so it should be treated as a sanity check rather than a full operating point.
- `threshold = 0.8` improves specificity slightly, but it gives up recall and remains below detector-only.
- The main systems result is now more conservative: the second stage no longer behaves like a brittle text generator, but it also does not improve over detector-only end-to-end performance.

## Practical Interpretation

- `0.2` is the more permissive triage mode when recall matters more than supported-positive purity.
- `0.5` is the current default balanced deployment mode.
- `0.8` is not attractive in practice; the gain in specificity does not justify the collapse in recall.

The strongest conclusion here is architectural rather than incremental: on `PrimeVul`, the detector is the performance driver, while the support scorer is currently best treated as a diagnostic filtering interface.

See [PRIMEVUL_SUPPORT_SCORER_ABLATIONS.md](D:/code/start/reports/PRIMEVUL_SUPPORT_SCORER_ABLATIONS.md) for the ablation that separates detector pass-through, probability-only, code-only, and heuristic-only controls.

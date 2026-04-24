# PrimeVul Detector + Evidence Scorer Operating Points

These operating points summarize the current `PrimeVul` two-stage system:

1. a high-recall `presence-only detector` (`Qwen2.5-Coder-1.5B-Instruct`, LoRA sequence classification)
2. a narrow non-generative `evidence scorer` that only decides whether a detector-positive alert is supported

All results below are measured on [secure_code_primevul_holdout_eval_balanced_2000.jsonl](D:/code/start/data/processed/secure_code_primevul_holdout_eval_balanced_2000.jsonl).

| Detector Threshold | Detector Positive Rate | Scorer Positive Rate | Unsupported Positive Share | Presence Accuracy | Vulnerable Recall | Safe Specificity | Precision | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `0.2` | 0.5252 | 0.3432 | 0.0750 | 0.7917 | 0.6349 | 0.9485 | 0.9250 | 0.7530 |
| `0.5` | 0.5185 | 0.4899 | 0.0640 | 0.9272 | 0.9171 | 0.9373 | 0.9360 | 0.9265 |
| `0.8` | 0.5078 | 0.1232 | 0.1364 | 0.5896 | 0.2128 | 0.9664 | 0.8636 | 0.3414 |

## Readout

- Unlike the earlier generative `detector + confirmer` family, this scorer line is not flat across thresholds.
- `threshold = 0.5` is the strongest balanced operating point by a wide margin.
- `threshold = 0.2` remains a viable recall-friendly mode, but it now behaves like a real triage point rather than a free lunch.
- `threshold = 0.8` is too conservative for this system family. It improves specificity slightly, but collapses recall and F1.
- The main systems result is that the second stage no longer behaves like a brittle text generator. Once we narrow it to a non-generative support decision, the two-stage pipeline becomes both high-recall and high-precision.

## Practical Interpretation

- `0.2` is the more permissive triage mode when recall matters more than supported-positive purity.
- `0.5` is the current default balanced deployment mode.
- `0.8` is not attractive in practice; the gain in specificity does not justify the collapse in recall.

The strongest conclusion here is architectural rather than incremental: on `PrimeVul`, the right second-stage abstraction is not a mini generative auditor, but a narrow evidence scorer / reranker.

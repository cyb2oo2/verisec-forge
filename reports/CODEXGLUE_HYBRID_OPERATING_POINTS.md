# CodeXGLUE Hybrid Operating Points

This note summarizes the threshold sweep for the discriminative detector
(`Qwen2.5-Coder-1.5B-Instruct + LoRA sequence classification`) and the
corresponding hybrid detector+a auditor system on balanced `eval1000`.

## Detector Threshold Sweep

Source report:
- `reports/secure_code_codexglue_cls_qwen15bcoder_lora_6000_v1_threshold_sweep_eval1000.json`

| Threshold | Presence Accuracy | Vulnerable Recall | Safe Specificity | Precision | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 0.2 | 0.527 | 0.956 | 0.098 | 0.5145 | 0.6690 |
| 0.5 | 0.565 | 0.488 | 0.642 | 0.5768 | 0.5287 |
| 0.8 | 0.581 | 0.188 | 0.974 | 0.8785 | 0.3097 |

Interpretation:
- `0.2` is a recall-heavy triage mode.
- `0.5` is a more balanced review mode.
- `0.8` is a conservative, specificity-first mode.

## Hybrid Detector + Auditor

Source summary:
- `reports/codexglue_hybrid_thresholds/secure_code_codexglue_hybrid_threshold_summary.json`
- `reports/codexglue_hybrid_thresholds_holdout2000/secure_code_codexglue_hybrid_threshold_summary.json`

| Threshold | Presence Accuracy | Vulnerable Recall | Safe Specificity | Evidence Support Rate | Format Pass Rate | Invalid Output Rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.2 | 0.527 | 0.956 | 0.098 | 0.071 | 1.000 | 0.000 |
| 0.5 | 0.565 | 0.488 | 0.642 | 0.577 | 1.000 | 0.000 |
| 0.8 | 0.581 | 0.188 | 0.974 | 0.893 | 1.000 | 0.000 |

Interpretation:
- The hybrid preserves the detector's binary tradeoff almost exactly.
- The auditor layer keeps the records well formed across all operating points.
- Higher thresholds improve safe-side trustworthiness and also increase
  evidence support, because only stronger detector positives are passed into
  the vulnerable path.

## Current Reading

This is the clearest systems result in the repository so far:

- a discriminative detector is better suited for high-recall vulnerability
  discovery on `CodeXGLUE`
- a generative auditor is better suited for stable, structured machine-readable
  secure-code outputs
- combining them creates a tunable detector+a auditor pipeline instead of
  forcing one model to solve both jobs at once

## Holdout Robustness

The same operating-point pattern holds on a larger balanced `holdout2000` slice:

| Threshold | Presence Accuracy | Vulnerable Recall | Safe Specificity | Evidence Support Rate | Format Pass Rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| 0.2 | 0.523 | 0.966 | 0.080 | 0.057 | 1.000 |
| 0.5 | 0.597 | 0.523 | 0.671 | 0.574 | 1.000 |
| 0.8 | 0.5785 | 0.193 | 0.964 | 0.8855 | 1.000 |

This matters because it shows the detector+a auditor story is not just a small
`eval1000` artifact. The same threshold tradeoff persists on a larger held-out
slice, while the auditor layer continues to deliver deterministic structured
output.

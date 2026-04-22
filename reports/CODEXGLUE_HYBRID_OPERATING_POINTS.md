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

| Threshold | Presence Accuracy | Vulnerable Recall | Safe Specificity | Detector Positive Rate | Evidence Support Rate | Unsupported Positive Share | Avg Latency (ms) | Format Pass Rate | Invalid Output Rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.2 | 0.527 | 0.956 | 0.098 | 0.929 | 0.071 | 1.000 | 919.73 | 1.000 | 0.000 |
| 0.5 | 0.565 | 0.488 | 0.642 | 0.423 | 0.577 | 1.000 | 919.73 | 1.000 | 0.000 |
| 0.8 | 0.581 | 0.188 | 0.974 | 0.107 | 0.893 | 1.000 | 919.73 | 1.000 | 0.000 |

Interpretation:
- The hybrid preserves the detector's binary tradeoff almost exactly.
- The auditor layer keeps the records well formed across all operating points.
- Higher thresholds improve safe-side trustworthiness and also increase
  evidence support, because more traffic is routed through the conservative
  safe path where records are always structurally complete.
- The current weak point is the positive path: `unsupported_positive_share = 1.0`
  at every threshold, which means classifier-positive cases are not yet arriving
  with concrete auditor-backed evidence spans.

## Current Reading

This is the clearest systems result in the repository so far:

- a discriminative detector is better suited for high-recall vulnerability
  discovery on `CodeXGLUE`
- a generative auditor is better suited for stable, structured machine-readable
  secure-code outputs
- combining them creates a tunable detector+a auditor pipeline instead of
  forcing one model to solve both jobs at once
- but in the current implementation, the detector contributes almost all of the
  vulnerable-path signal while the auditor mainly contributes output structure

## Holdout Robustness

The same operating-point pattern holds on a larger balanced `holdout2000` slice:

| Threshold | Presence Accuracy | Vulnerable Recall | Safe Specificity | Detector Positive Rate | Evidence Support Rate | Unsupported Positive Share | Avg Latency (ms) | Format Pass Rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.2 | 0.523 | 0.966 | 0.080 | 0.9430 | 0.0570 | 1.000 | 1738.94 | 1.000 |
| 0.5 | 0.597 | 0.523 | 0.671 | 0.4260 | 0.5740 | 1.000 | 1738.94 | 1.000 |
| 0.8 | 0.5785 | 0.193 | 0.964 | 0.1145 | 0.8855 | 1.000 | 1738.94 | 1.000 |

This matters because it shows the detector+a auditor story is not just a small
`eval1000` artifact. The same threshold tradeoff persists on a larger held-out
slice, while the auditor layer continues to deliver deterministic structured
output. It also sharpens the open problem: even on the larger held-out slice,
the positive branch still lacks evidence-bearing auditor confirmations, so the
next research step should focus on making the auditor add specific evidence
rather than only format stability.

## Evidence-Gated Negative Result

We also tested a stricter hybrid policy:

- detector must be positive
- auditor must supply evidence before the final record is allowed onto the
  vulnerable path

This collapses immediately on both `eval1000` and `holdout2000`:

- `detector_positive_rate = 0.0`
- `vulnerable_recall = 0.0`
- `safe_specificity = 1.0`

This is a useful negative result, not a dead end. It shows that the current
auditor is still acting mainly as a structured-output layer, not as a true
positive-case evidence confirmer. In other words, the next step is not "tune the
threshold harder", but "teach the auditor how to attach reliable evidence to
positive detections."

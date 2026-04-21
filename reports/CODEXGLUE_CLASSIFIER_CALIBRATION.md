# CodeXGLUE Classifier Calibration

Source:
- [secure_code_codexglue_cls_qwen15bcoder_lora_6000_v1_calibration_eval1000.json](/D:/code/start/reports/secure_code_codexglue_cls_qwen15bcoder_lora_6000_v1_calibration_eval1000.json)
- [secure_code_codexglue_cls_qwen15bcoder_lora_6000_v1_calibration_holdout2000.json](/D:/code/start/reports/secure_code_codexglue_cls_qwen15bcoder_lora_6000_v1_calibration_holdout2000.json)

Classifier:
- `Qwen2.5-Coder-1.5B-Instruct + LoRA sequence classification`
- dataset: balanced `CodeXGLUE eval1000`

## Summary

- Expected calibration error: `0.0691`
- The most stable region is not the extreme low-confidence or mid-high region, but the broad `0.4-0.6` bucket.
- The `0.8-1.0` bucket is the cleanest high-specificity zone and is the best candidate for conservative trustworthy auditing.
- On the larger `holdout2000`, the same qualitative shape holds and calibration improves slightly (`ECE = 0.0577`).

## Bucket Table

| Bucket | Count | Share | Avg Probability | Empirical Vulnerable Rate | Gap | Suggested Policy |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `0.0-0.2` | 71 | 0.071 | 0.1159 | 0.3099 | 0.1939 | Recall-heavy triage only; too underconfident for conservative use |
| `0.2-0.4` | 231 | 0.231 | 0.3192 | 0.4286 | 0.1094 | Still recall-oriented; useful for broad sweep, not trustworthy auditing |
| `0.4-0.6` | 511 | 0.511 | 0.4954 | 0.4814 | 0.0140 | Best balanced review zone |
| `0.6-0.8` | 80 | 0.080 | 0.6586 | 0.4875 | 0.1711 | Specificity-favoring, but overconfident relative to empirical rate |
| `0.8-1.0` | 107 | 0.107 | 0.9647 | 0.8785 | 0.0862 | Best conservative trustworthy zone |

## Reading

This calibration view sharpens the detector+a auditor story:

- If the goal is **recall-heavy triage**, thresholds around `0.2` are appropriate, but they come with very weak safe-side trustworthiness.
- If the goal is **balanced review**, the best zone is around `0.5`, which is also where the probability buckets are best aligned with empirical vulnerability rates.
- If the goal is **conservative trustworthy auditing**, thresholds around `0.8` make the most sense. They sacrifice recall, but they produce the strongest safe-side behavior and the cleanest evidence-support profile in the stitched hybrid.

## Holdout2000 Check

The larger balanced `holdout2000` slice keeps the same basic pattern:

| Bucket | Count | Avg Probability | Empirical Vulnerable Rate | Gap |
| --- | ---: | ---: | ---: | ---: |
| `0.0-0.2` | 114 | 0.0868 | 0.2982 | 0.2114 |
| `0.2-0.4` | 525 | 0.3279 | 0.4000 | 0.0721 |
| `0.4-0.6` | 945 | 0.4943 | 0.4889 | 0.0054 |
| `0.6-0.8` | 187 | 0.6513 | 0.5401 | 0.1112 |
| `0.8-1.0` | 229 | 0.9632 | 0.8428 | 0.1204 |

The important point is not that the detector is perfectly calibrated. It is not.
The important point is that the *policy split is stable*: the `0.4-0.6` zone is
still the best balanced review region, and the `0.8+` zone is still the best
conservative trustworthy region.

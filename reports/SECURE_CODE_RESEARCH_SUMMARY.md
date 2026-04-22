# Secure Code Research Summary

This summary consolidates the current `PrimeVul eval244` secure-code reasoning results.

| Model | Label Accuracy | Format Pass Rate | Invalid Output Rate | High-Confidence Error Rate | Avg Tokens | Dominant Label Error | Dominant Format Error |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| Base 0.5B | 0.4098 | 0.5410 | 0.2131 | 0.1639 | 41.8443 | false_negative | hard_fail |
| SFT 0.5B | 0.4795 | 0.8279 | 0.1598 | 0.0287 | 35.9918 | false_negative | hard_fail |
| Base 1.5B | 0.0697 | 0.8484 | 0.1311 | 0.1066 | 95.4426 | false_positive | hard_fail |
| Hard DPO v2 | 0.2090 | 0.3033 | 0.6926 | 0.0205 | 57.6475 | false_negative | hard_fail |
| Calibrated LoRA-only DPO v1 | 0.3648 | 0.6598 | 0.2910 | 0.0082 | 34.6475 | false_negative | hard_fail |
| Label-focused LoRA-only DPO v1 | 0.2418 | 0.4549 | 0.2541 | 0.0738 | 30.0738 | false_negative | hard_fail |

## Key Findings

- `SFT 0.5B` remains the strongest overall model on the balanced secure-code benchmark.
- `1.5B base` produces longer, more security-flavored analyses, but is badly over-calibrated and over-detects vulnerabilities.
- Full-model DPO variants damage the output protocol more than they improve secure-code judgment.
- LoRA-only DPO is safer than full-model DPO, but still has not surpassed the SFT anchor.

## Research Readout

- Best current model by label accuracy: `SFT 0.5B` at `0.4795`.
- `Base 0.5B`: accuracy `0.4098`, format `0.5410`, invalid `0.2131`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.9-1.0`.
- `SFT 0.5B`: accuracy `0.4795`, format `0.8279`, invalid `0.1598`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.5-0.74`.
- `Base 1.5B`: accuracy `0.0697`, format `0.8484`, invalid `0.1311`, dominant label error `false_positive`, dominant format error `hard_fail`, best confidence bucket `missing`.
- `Hard DPO v2`: accuracy `0.2090`, format `0.3033`, invalid `0.6926`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.0-0.49`.
- `Calibrated LoRA-only DPO v1`: accuracy `0.3648`, format `0.6598`, invalid `0.2910`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.0-0.49`.
- `Label-focused LoRA-only DPO v1`: accuracy `0.2418`, format `0.4549`, invalid `0.2541`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.9-1.0`.

## Failure Taxonomy Readout

- `Base 0.5B` is mainly a false-negative model: it misses vulnerable code and is poorly calibrated when highly confident.
- `SFT 0.5B` keeps the same dominant semantic error class (`false_negative`) but sharply reduces protocol breakage and high-confidence mistakes.
- `Base 1.5B` is qualitatively different: its dominant failure is `false_positive`, which matches the observed over-detection bias.
- The DPO variants split into two failure modes: full-model preference tuning collapses into `hard_fail` format errors, while LoRA-only DPO is structurally safer but still reintroduces more semantic errors than the SFT anchor.

## Practical Conclusion

- The strongest secure-code recipe in this repo is still `balanced PrimeVul + completion-only SFT + tolerant parser`.
- The most trustworthy current model is not the one that sounds most security-fluent. `Base 1.5B` looks more expert but is much less calibrated than the `0.5B` SFT checkpoint.
- The next research step should prioritize benchmark expansion, calibration analysis, and failure taxonomy over more aggressive preference tuning by default.

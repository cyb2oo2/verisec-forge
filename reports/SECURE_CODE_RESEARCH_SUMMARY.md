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

- `SFT 0.5B` is currently the strongest run by label accuracy (`0.4795`).
- `Base 1.5B` is currently the most protocol-stable run by format pass rate (`0.8484`).
- `Calibrated LoRA-only DPO v1` has the lowest high-confidence error rate (`0.0082`) among the summarized runs.
- DPO has not surpassed the best SFT anchor yet: `SFT 0.5B` (`0.4795`) still outperforms the strongest DPO run `Calibrated LoRA-only DPO v1` (`0.3648`).
- `Base 1.5B` is the clearest over-detection outlier in this slice: its dominant label error is `false_positive`, and its label accuracy is `0.0697`.
- The strongest SFT run improves over the strongest base run by `0.0697` label-accuracy points.

## Research Readout

- `Base 0.5B`: accuracy `0.4098`, format `0.5410`, invalid `0.2131`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.9-1.0`.
- `SFT 0.5B`: accuracy `0.4795`, format `0.8279`, invalid `0.1598`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.5-0.74`.
- `Base 1.5B`: accuracy `0.0697`, format `0.8484`, invalid `0.1311`, dominant label error `false_positive`, dominant format error `hard_fail`, best confidence bucket `missing`.
- `Hard DPO v2`: accuracy `0.2090`, format `0.3033`, invalid `0.6926`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.0-0.49`.
- `Calibrated LoRA-only DPO v1`: accuracy `0.3648`, format `0.6598`, invalid `0.2910`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.0-0.49`.
- `Label-focused LoRA-only DPO v1`: accuracy `0.2418`, format `0.4549`, invalid `0.2541`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.9-1.0`.

## Failure Taxonomy Readout

- The most common dominant semantic error across the summarized runs is `false_negative`.
- The most common dominant protocol error across the summarized runs is `hard_fail`.
- `SFT 0.5B` is the clearest example of the repo's current precision-oriented pattern: it stays format-stable (`0.8279`) while remaining dominated by `false_negative`.

## Practical Conclusion

- The current best benchmark-facing checkpoint in this summary is `SFT 0.5B`, based on `label_accuracy = 0.4795`.
- If protocol stability is the priority, `Base 1.5B` is the current strongest option with `format_pass_rate = 0.8484`.
- If calibration risk is the priority, `Calibrated LoRA-only DPO v1` is the safest current choice in this slice with `high_confidence_error_rate = 0.0082`.
- The main unresolved semantic problem across this run family is still `false_negative`.

## Dual-System Follow-up

- On the newer `CodeXGLUE` branch, the strongest practical result is now a detector+a auditor split rather than a single generative auditor.
- The discriminative detector preserves much stronger vulnerable recall than the structured JSON auditor, while the auditor preserves deterministic output formatting.
- The current limitation of that hybrid is now clearer: classifier-positive cases still do not come with concrete auditor-backed evidence spans, so the hybrid is best understood as a policy-tunable structured review shell rather than a fully evidence-grounded second-stage auditor.
- A stricter evidence-gated hybrid confirms that diagnosis. Once we require classifier-positive cases to also carry auditor evidence before entering the vulnerable path, the system collapses to `vulnerable_recall = 0.0` and `safe_specificity = 1.0`. That is a strong negative result: the missing piece is not threshold tuning, but evidence-grounded positive auditing.
- A follow-up `detector_positive_auditor` training line did not fix that gap. As a standalone auditor it regressed sharply (`label_accuracy = 0.336`, `format_pass_rate = 0.659`, `vulnerable_recall = 0.004` on `CodeXGLUE eval1000`), and when stitched back into the hybrid it only nudged `unsupported_positive_share` from `1.0` down to roughly `0.998-0.999`. Under evidence-gated evaluation it again collapses to effectively zero positive traffic. This makes the negative result stronger: the current auditor family is not yet learning new positive-case evidence, only reshaping detector outputs.

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

- On the `CodeXGLUE` branch, the strongest practical result is now a detector + auditor split rather than a single generative auditor.
- The discriminative detector preserves much stronger vulnerable recall than the structured JSON auditor, while the auditor preserves deterministic output formatting.
- A stricter evidence-gated hybrid on `CodeXGLUE` confirms the earlier diagnosis. Once we require classifier-positive cases to also carry auditor evidence before entering the vulnerable path, the system collapses to `vulnerable_recall = 0.0` and `safe_specificity = 1.0`.
- A follow-up `detector_positive_auditor` training line did not fix that gap. As a standalone auditor it regressed sharply (`label_accuracy = 0.336`, `format_pass_rate = 0.659`, `vulnerable_recall = 0.004` on `CodeXGLUE eval1000`), and when stitched back into the hybrid it only nudged `unsupported_positive_share` from `1.0` down to roughly `0.998-0.999`.
- The `PrimeVul presence-only detector` sharpened that broader systems conclusion. A narrow `1.5B Coder` classifier trained on a balanced `3000`-example PrimeVul subset reaches `presence_accuracy = 0.9524`, `vulnerable_recall = 0.9709`, and `safe_specificity = 0.9339` on `holdout2000`, with `0` exact code overlap against the held-out eval slice.
- A first `PrimeVul detector + evidence confirmer` result then gave the repo a more plausible second-stage story. Starting from the same `presence-only detector`, the confirmer reduces positive traffic to a smaller high-confidence set with `precision = 0.9519`, `safe_specificity = 0.9798`, `unsupported_positive_share = 0.0027`, and `avg_evidence_items_per_positive = 1.5294`, while still preserving `vulnerable_recall = 0.3987`.
- Follow-up generative confirmer ablations did not improve that boundary. Hard-negative weighting, supported-positive shaping, and family-aware richer targets all underperform the original confirmer anchor.
- The `PrimeVul detector + support scorer` line remains useful, but the new ablation changes the claim. The full support scorer reaches `presence_accuracy = 0.9272`, `vulnerable_recall = 0.9171`, `safe_specificity = 0.9373`, `precision = 0.9360`, and `f1 = 0.9265`, but detector-only / probability pass-through is stronger at `presence_accuracy = 0.9524` and `f1 = 0.9533`.
- The current best system-level conclusion is therefore detector-first: on `PrimeVul`, the narrow presence detector is the performance driver, while the support scorer is currently a diagnostic second-stage filtering interface rather than an end-to-end improvement.
- A first `CodeXGLUE detector + support scorer` follow-up makes that conclusion more precise rather than simply broader. On `holdout2000`, the same non-generative scorer idea behaves like a conservative confirmation layer, not a new system winner: the default `detector=0.5, scorer=0.5` point reaches `presence_accuracy = 0.5690`, `vulnerable_recall = 0.3030`, `safe_specificity = 0.8350`, and `precision = 0.6474`.
- The best `CodeXGLUE` scorer grid point by balanced accuracy is `detector=0.5, scorer=0.2`, with `presence_accuracy = 0.6055`, `vulnerable_recall = 0.4800`, `safe_specificity = 0.7310`, `precision = 0.6409`, and `f1 = 0.5489`. That is close to, but still below, the full-balanced detector-only holdout result (`presence_accuracy = 0.6135`, best held-out `f1 = 0.6741`).
- The new `CodeXGLUE` failure breakdown shows why: at that best scorer point, `90.38%` of false negatives are detector misses and only `9.62%` are scorer rejections. So the next CodeXGLUE gains should come primarily from detector training, not more scorer threshold tuning.
- That cross-benchmark contrast is now one of the most useful findings in the repo. A non-generative second stage is still the right abstraction, but its payoff depends on whether the benchmark really supports a "supported vs unsupported positive" decision. On `PrimeVul`, that decomposition is powerful. On `CodeXGLUE`, it currently sharpens specificity more than it improves the overall detector.

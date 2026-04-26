# PrimeVul Support Scorer Ablations

These ablations test whether the `PrimeVul` support scorer result is driven by code evidence, detector probability, heuristic keyword priors, or the full combined prompt.

Two label definitions are now separated:

- `heuristic_support`: positive only when the sample is vulnerable and the heuristic evidence extractor finds tracked security keywords.
- `alert_validity`: positive when the detector-positive alert is truly vulnerable according to the source label.

All runs use the same detector-positive support-scorer train/eval rows:

- train rows: `1547`
- train supported positives: `1305`
- train negatives: `242`
- hard-negative balanced train rows:
  - `1:1`: `242` positives / `242` negatives
  - `2:1`: `484` positives / `242` negatives
  - `4:1`: `968` positives / `242` negatives
- holdout detector-positive rows: `926`
- holdout supported positives: `740`
- holdout negatives: `186`
- alert-validity train rows: `1490` true alerts / `57` false alerts
- alert-validity holdout rows: `867` true alerts / `59` false alerts

The strong class imbalance is important: weak support-scorer variants can look good on the detector-positive subset by simply accepting almost everything.

## Detector-Positive Subset Metrics

These metrics evaluate only the detector-positive support-scorer subset.

| Variant | Input Available To Scorer | Accuracy | Recall | Specificity | Precision | TP | TN | FP | FN |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| full support scorer | detector probability + code | 0.9449 | 0.9446 | 0.9462 | 0.9860 | 699 | 176 | 10 | 41 |
| probability only | detector probability only | 0.7991 | 1.0000 | 0.0000 | 0.7991 | 740 | 0 | 186 | 0 |
| no probability | code without detector probability | 0.7894 | 0.9851 | 0.0108 | 0.7985 | 729 | 2 | 184 | 11 |
| no probability, hard negatives 1:1 | code without detector probability | 0.3834 | 0.2770 | 0.8065 | 0.8506 | 205 | 150 | 36 | 535 |
| no probability, hard negatives 2:1 | code without detector probability | 0.5518 | 0.5351 | 0.6183 | 0.8480 | 396 | 115 | 71 | 344 |
| no probability, hard negatives 4:1 | code without detector probability | 0.7635 | 0.9284 | 0.1075 | 0.8054 | 687 | 20 | 166 | 53 |
| alert validity, no probability, hard negatives 8:1 | code without detector probability | 0.9006 | 0.9550 | 0.1017 | 0.9398 | 828 | 6 | 53 | 39 |
| code only | raw code only | 0.7765 | 0.9716 | 0.0000 | 0.7945 | 719 | 0 | 186 | 21 |
| heuristic only | tracked keyword counts only | 0.9449 | 1.0000 | 0.7258 | 0.9355 | 740 | 135 | 51 | 0 |

## End-To-End Holdout Metrics

These metrics stitch each scorer back behind the same `PrimeVul` detector on `secure_code_primevul_holdout_eval_balanced_2000.jsonl`.

| Variant | Presence Accuracy | Vulnerable Recall | Safe Specificity | Precision | F1 | Acceptance On Detector Positives | Scorer Behavior | Delta F1 vs Detector |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| detector only / probability pass-through | 0.9524 | 0.9709 | 0.9339 | 0.9363 | 0.9533 | 1.0000 | pass_through | 0.0000 |
| full support scorer | 0.9272 | 0.9171 | 0.9373 | 0.9360 | 0.9265 | 0.9449 | filtering | -0.0268 |
| no probability | 0.9462 | 0.9574 | 0.9351 | 0.9365 | 0.9468 | 0.9860 | weak_filter | -0.0065 |
| no probability, hard negatives 1:1 | 0.5980 | 0.2329 | 0.9630 | 0.8631 | 0.3668 | 0.2603 | filtering | -0.5865 |
| no probability, hard negatives 2:1 | 0.7223 | 0.4838 | 0.9608 | 0.9251 | 0.6353 | 0.5043 | filtering | -0.3180 |
| no probability, hard negatives 4:1 | 0.9138 | 0.8914 | 0.9362 | 0.9332 | 0.9118 | 0.9212 | filtering | -0.0415 |
| alert validity, no probability, hard negatives 8:1 | 0.9339 | 0.9272 | 0.9406 | 0.9398 | 0.9335 | 0.9514 | weak_filter | -0.0198 |
| code only | 0.9406 | 0.9474 | 0.9339 | 0.9348 | 0.9410 | 0.9773 | weak_filter | -0.0123 |
| heuristic only | 0.8858 | 0.8287 | 0.9429 | 0.9355 | 0.8789 | 0.8542 | filtering | -0.0744 |

## Readout

- The strongest end-to-end PrimeVul result remains the detector itself, not the support scorer.
- `probability_only` degenerates into detector pass-through. It has perfect recall and zero specificity on the detector-positive support subset, so it is not a real support decision.
- `no_probability` and `code_only` also mostly accept detector-positive examples. They preserve detector performance but do not produce meaningful second-stage filtering.
- `heuristic_only` is surprisingly strong on the detector-positive subset, but loses substantial end-to-end recall. It is best interpreted as a keyword-prior baseline, not evidence grounding.
- Hard-negative balancing successfully makes the scorer reject detector-positive safe examples, but it does not improve the two-stage system. The `1:1` and `2:1` variants over-filter, while `4:1` is a gentler middle point that still remains below detector-only.
- `alert_validity` is cleaner than `heuristic_support`, but the current no-probability scorer still remains a weak filter: it rejects only `6` of `59` detector false positives while also rejecting `39` true positives.
- The original full support scorer is not a benchmark-performance improvement over detector-only. Its value is diagnostic: it gives the repo a controlled second-stage interface, but future claims should not say it is the source of the PrimeVul detection gain.
- The evaluator now reports `is_pass_through`, `scorer_behavior`, `scorer_acceptance_rate_on_detector_positive`, and `delta_vs_detector_only` so future scorer reports cannot silently inherit detector performance. New classifier predictions also include `vuln_probability`, so future scorer threshold sweeps do not need separate long-running probability exports.

## Updated Claim

The safe claim is:

> On `PrimeVul`, a narrow discriminative detector is the main performance driver. A second-stage support scorer is useful for studying confirmation and filtering behavior, but the current scorer does not improve over detector-only end-to-end performance.

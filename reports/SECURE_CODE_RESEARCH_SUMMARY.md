# Secure Code Research Summary

This summary consolidates the current `PrimeVul eval244` secure-code reasoning results.

| Model | Label Accuracy | Format Pass Rate | Invalid Output Rate | High-Confidence Error Rate | Avg Tokens | Dominant Label Error | Dominant Format Error |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| Base 0.5B | 0.4098 | 0.5410 | 0.2131 | 0.1639 | 41.8443 | false_negative | hard_fail |
| SFT 0.5B | 0.4795 | 0.8279 | 0.1598 | 0.0287 | 35.9918 | false_negative | hard_fail |
| SFT 0.5B (`safe->none`) | 0.4959 | 0.8033 | 0.1516 | 0.0328 | 36.5123 | false_negative | hard_fail |
| Base 1.5B | 0.0697 | 0.8484 | 0.1311 | 0.1066 | 95.4426 | false_positive | hard_fail |
| Hard DPO v2 | 0.2090 | 0.3033 | 0.6926 | 0.0205 | 57.6475 | false_negative | hard_fail |
| Calibrated LoRA-only DPO v1 | 0.3648 | 0.6598 | 0.2910 | 0.0082 | 34.6475 | false_negative | hard_fail |
| Label-focused LoRA-only DPO v1 | 0.2418 | 0.4549 | 0.2541 | 0.0738 | 30.0738 | false_negative | hard_fail |

## Key Findings

- `SFT 0.5B` remains the strongest family overall on the balanced secure-code benchmark, and a small target cleanup (`safe -> none`) now gives the best `eval244` result.
- Verifier-style second review is promising only when the verifier emits canonical, structurally trustworthy labels. A recall-heavy verifier can flip safe predictions, but most of its candidate overrides use generic labels such as `vulnerable` or `defensive-security-vulnerability`, which are too noisy to accept directly.
- `1.5B base` produces longer, more security-flavored analyses, but is badly over-calibrated and over-detects vulnerabilities.
- Full-model DPO variants damage the output protocol more than they improve secure-code judgment.
- LoRA-only DPO is safer than full-model DPO, but still has not surpassed the SFT anchor.

## Research Readout

- Best current model by label accuracy on `eval244`: `SFT 0.5B (safe->none)` at `0.4959`.
- `Base 0.5B`: accuracy `0.4098`, format `0.5410`, invalid `0.2131`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.9-1.0`.
- `SFT 0.5B`: accuracy `0.4795`, format `0.8279`, invalid `0.1598`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.5-0.74`.
- `SFT 0.5B (safe->none)`: accuracy `0.4959`, format `0.8033`, invalid `0.1516`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.75-0.89`.
- `Base 1.5B`: accuracy `0.0697`, format `0.8484`, invalid `0.1311`, dominant label error `false_positive`, dominant format error `hard_fail`, best confidence bucket `missing`.
- `Hard DPO v2`: accuracy `0.2090`, format `0.3033`, invalid `0.6926`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.0-0.49`.
- `Calibrated LoRA-only DPO v1`: accuracy `0.3648`, format `0.6598`, invalid `0.2910`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.0-0.49`.
- `Label-focused LoRA-only DPO v1`: accuracy `0.2418`, format `0.4549`, invalid `0.2541`, dominant label error `false_negative`, dominant format error `hard_fail`, best confidence bucket `0.9-1.0`.
- `Evidence-only + self-verifier`: no semantic change on `eval244`; the same model can re-read low-confidence safe outputs, but it does not actually overturn them.
- `Evidence-only + presence verifier (loose)`: the first verifier route that produced real overrides, but most flips relied on generic vulnerability labels and raised high-confidence error rate too much to count as a trustworthy improvement.
- `Evidence-only + presence verifier (strict)`: once overrides are limited to canonical `cwe-*` types with clean parsing, all `10` loose overrides disappear. This shows the recall signal is real but not yet specific enough.
- `Evidence-only + oversample verifier (strict)`: produces exactly `1` accepted override. It preserves structure, but the gain is too small to move the benchmark materially.
- `Verifier-canonical SFT v1`: teaches a dedicated second-pass reviewer to avoid generic labels, but becomes too conservative. On `eval244` it reaches `label_accuracy = 0.5000` with `safe_specificity = 1.0000` and `vulnerable_recall = 0.0246`, which is not enough to function as a useful recall-recovery verifier.
- `Failure-driven verifier SFT (seed200)`: trains a verifier on real `false_negative` cases from the strongest `evidence_only` model plus matched safe predictions. Standalone, it is much more willing to surface vulnerable samples (`vulnerable_recall = 0.0574`), but it also becomes much less trustworthy (`high_confidence_error_rate = 0.2623`) and is therefore not suitable as a direct replacement for the main auditor.
- `Evidence-only + failure-driven verifier (strict-mid gate)`: under a canonical, moderately relaxed ensemble gate, this verifier yields `1` accepted override. It slightly raises `presence_accuracy` (`0.5123 -> 0.5164`) and `vulnerable_recall` (`0.0328 -> 0.0410`) while preserving `safe_specificity = 0.9918`, but it still does not improve exact `label_accuracy`.
- `Failure-driven verifier SFT (seed800)`: scaling the same idea to a larger mined failure set does not automatically make the verifier cleaner. On `eval244` it keeps similar `label_accuracy = 0.4631`, but `format_pass_rate` drops to `0.4918` and `high_confidence_error_rate` remains high at `0.0984`. This suggests the issue is not just data volume; the verifier target itself still invites malformed or overconfident behavior.
- `Failure-driven compact verifier (seed200)`: aggressively shortening the verifier target does not rescue the verifier either. It raises standalone `vulnerable_recall` to `0.1639`, but collapses `safe_specificity` to `0.4508` and `label_accuracy` to `0.2254`, showing that shorter outputs alone do not create a trustworthy second-pass model.
- `Failure-driven decision-only verifier (seed200)`: narrowing the verifier further to a tiny fixed-shape decision object is more stable than the compact variant, but still not strong enough to beat the main auditor. As a standalone verifier it reaches `label_accuracy = 0.4262`, `vulnerable_recall = 0.0492`, and `format_pass_rate = 0.5984`, which is better-behaved than the compact verifier but still materially weaker than the default failure-driven verifier.
- `Evidence-only + failure-driven decision-only verifier (strict-mid gate)`: this is the first verifier route with more than one accepted canonical override (`2` overrides on `eval244`), but the extra flexibility does not turn into a net gain. `label_accuracy` slips to `0.4877`, `safe_specificity` drops to `0.9754`, and `vulnerable_recall` stays at `0.0328`, so the second-pass reviewer still cannot improve the main auditor under a trustworthy acceptance policy.
- `Failure-driven binary-judge verifier (seed200)`: restricting the verifier to a binary judgment with fixed explanation and fix strings does not make it trustworthy by itself. Standalone, it becomes highly recall-heavy (`vulnerable_recall = 0.4098`) but collapses `safe_specificity` to `0.1803`, with `label_accuracy = 0.0943` and `high_confidence_error_rate = 0.6025`.
- `Evidence-only + failure-driven binary-judge verifier (strict-mid gate)`: a strict canonical gate can partially tame that instability, accepting `9` overrides on `eval244`. But the net effect is still negative: `vulnerable_recall` rises to `0.0492`, while `label_accuracy` drops to `0.4672`, `safe_specificity` falls to `0.9344`, and `high_confidence_error_rate` rises to `0.0615`.
- `Failure-driven label-only verifier (seed200)`: removing evidence responsibility and shrinking the verifier to near-reranker form does make it cleaner than the binary-judge variant. Standalone, it reaches `label_accuracy = 0.1885`, `vulnerable_recall = 0.2787`, `safe_specificity = 0.3770`, and `format_pass_rate = 0.8197`, which is substantially more stable than the binary-judge verifier but still far too over-sensitive to trust by itself.
- `Evidence-only + failure-driven label-only verifier (strict-mid gate)`: once the same canonical mid-threshold gate is applied, this verifier contributes `0` accepted overrides. That is a useful boundary result: the model is now structured enough to avoid obvious protocol collapse, but it still does not produce sufficiently specific, high-confidence new evidence to overturn any safe prediction under a trustworthy policy.

## Failure Taxonomy Readout

- `Base 0.5B` is mainly a false-negative model: it misses vulnerable code and is poorly calibrated when highly confident.
- `SFT 0.5B` keeps the same dominant semantic error class (`false_negative`) but sharply reduces protocol breakage and high-confidence mistakes.
- Canonicalizing safe examples to `vulnerability_type = none` improves the SFT anchor further. The gain is modest but real: `false_negative` falls from `79` to `72` on `eval244` without the severe calibration collapse seen in the earlier recall-focused experiment.
- `Base 1.5B` is qualitatively different: its dominant failure is `false_positive`, which matches the observed over-detection bias.
- The DPO variants split into two failure modes: full-model preference tuning collapses into `hard_fail` format errors, while LoRA-only DPO is structurally safer but still reintroduces more semantic errors than the SFT anchor.
- Verifier experiments split in a similarly revealing way: self-verification is too weak to change decisions, while cross-model verification can recover some missed vulnerabilities only when we allow generic labels. As soon as we require canonical `cwe-*` outputs, the apparent gain mostly vanishes.
- A dedicated verifier-only SFT checkpoint confirms the same tradeoff from the other side: once we strongly constrain the reviewer toward canonical outputs, it stops hallucinating labels but also stops surfacing most true vulnerabilities.
- A failure-driven verifier built from the main model's own `false_negative` cases does recover more vulnerable predictions than the generic canonical verifier, which is an encouraging sign. But the recovered signal is still too noisy to cleanly improve exact secure-code labeling under a strict acceptance rule.
- Enlarging the failure-driven verifier dataset from `seed200` to `seed800` does not fix that noise. The larger verifier becomes less structurally stable, which suggests that simply mining more misses is not enough without stronger output-shape control or narrower verifier targets.
- Narrowing the output target by itself also fails. The compact verifier becomes much shorter, but it still emits malformed or semantically untrustworthy outputs, which means the remaining problem is not verbosity alone but the verifier objective itself.
- A still narrower decision-only verifier is the most useful negative result in this branch: it proves that stronger structural narrowing can increase accepted overrides, but the accepted flips still fail to improve recall in a meaningful way and start to erode specificity. That makes the current verifier bottleneck much clearer: the open problem is no longer just output shape, but how to teach a second-pass model to add genuinely new vulnerability evidence without drifting into noisy over-detection.
- A binary-judge verifier sharpens that conclusion further. Once we remove most of the generation freedom, the verifier does become more decisive, but it mainly becomes decisively over-sensitive. Even after a strict canonical gate rescues the output protocol, the accepted overrides still degrade overall labeling. That suggests the remaining bottleneck is not simply wording or JSON shape, but how to learn a second-pass decision boundary that adds real evidence instead of just a stronger vulnerable prior.
- A label-only verifier closes the loop on that design space. It is cleaner and more protocol-stable than the binary-judge variant, but once we require canonical, high-confidence overrides it becomes too weak to change any decision at all. So the verifier bottleneck is now quite specific: we can build second-pass models that are expressive but noisy, or neat but inert, but we still cannot make them both trustworthy and useful at once.
- The verifier branch is therefore mature enough to support a clear project-level claim: current second-pass models can be made generic, canonical, compact, decision-only, or binary-judge style, but none of those variants yet produce a trustworthy positive net gain over the main SFT auditor. The consistent pattern is that recall can be purchased, but only by giving up too much specificity or calibration.

## Practical Conclusion

- The strongest secure-code recipe in this repo is still `balanced PrimeVul + completion-only SFT + tolerant parser`.
- The most trustworthy current model is not the one that sounds most security-fluent. `Base 1.5B` looks more expert but is much less calibrated than the `0.5B` SFT checkpoint.
- The next research step should prioritize benchmark expansion, calibration analysis, and failure taxonomy over more aggressive preference tuning by default.

## CodeXGLUE Coder-1.5B Readout

We also ran a second mainline on a shorter, more community-typical benchmark:

- dataset: `CodeXGLUE defect detection`
- model: `Qwen/Qwen2.5-Coder-1.5B-Instruct`
- eval slice: balanced `eval1000`

| Model | Presence Accuracy | Vulnerable Recall | Safe Specificity | Label Accuracy | Format Pass Rate | Invalid Output Rate | High-Confidence Error Rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Base 1.5B Coder | 0.437 | 0.358 | 0.516 | 0.330 | 0.886 | 0.093 | 0.014 |
| SFT 1.5B Coder (`safe->none`, 3k) | 0.477 | 0.078 | 0.876 | 0.477 | 0.939 | 0.061 | 0.248 |
| SFT 1.5B Coder (`safe->none`, 6k) | 0.473 | 0.072 | 0.874 | 0.473 | 0.937 | 0.061 | 0.227 |
| SFT 1.5B Coder (`standard`, 6k) | 0.477 | 0.078 | 0.876 | 0.477 | 0.939 | 0.061 | 0.229 |
| SFT 1.5B Coder (`evidence_only`, 6k) | 0.474 | 0.082 | 0.866 | 0.474 | 0.942 | 0.058 | 0.182 |
| SFT 1.5B Coder (`recall_focused`, 6k) | 0.472 | 0.076 | 0.868 | 0.472 | 0.935 | 0.064 | 0.185 |
| SFT 1.5B Coder (`vulnerable_oversample_clean`, 6k) | 0.482 | 0.138 | 0.826 | 0.482 | 0.940 | 0.059 | 0.405 |
| Classifier 1.5B Coder (LoRA, 6k) | 0.567 | 0.492 | 0.642 | 0.567 | n/a | n/a | n/a |
| Hybrid (`classifier detect` + `evidence_only audit`) | 0.567 | 0.492 | 0.642 | 0.567 | 1.000 | 0.000 | 0.000* |

- `CodeXGLUE` validates that earlier `PrimeVul` experiments were not purely "too much benchmark realism for a small model." On shorter function-level data, the pipeline is healthier and easier to train.
- But it also strengthens the deeper conclusion: even on the shorter binary benchmark, structured generative SFT still tends to move the model toward conservative safe-biased behavior.
- The `standard 6k` run is especially important. It shows that low recall is not primarily caused by `safe->none` canonicalization, because removing that cleanup barely changes the operating point.
- Scaling balanced data from `3k -> 6k` also barely changes recall, so the current bottleneck is not simply dataset size.
- The only recipe that materially improves `vulnerable_recall` is `vulnerable_oversample_clean`, but its `high_confidence_error_rate = 0.405` makes it hard to justify as a trustworthy auditor.
- The discriminative LoRA classifier is the clearest control result in this branch. It substantially outperforms the generative JSON models on both binary accuracy and vulnerable recall, which means the remaining bottleneck is not just model size or dataset fit.
- The new hybrid detector+auditor pipeline turns that classifier result into a systems result. By letting the classifier decide `has_vulnerability` and the generative auditor provide structured fields, we preserve `presence_accuracy = 0.567` and `vulnerable_recall = 0.492` while achieving `format_pass_rate = 1.0`.
- This hybrid is not a perfect secure-code judge yet: it still inherits the classifier's precision/specificity tradeoff, and many classifier-positive cases do not come with strong evidence spans. But it is the first route in the repo that cleanly separates "high-recall detection" from "well-formed structured auditing."
- The current CodeXGLUE conclusion is therefore: data-model fit matters, but under this repo's generative JSON setup the recall/calibration tradeoff remains the real open problem.

*Hybrid `high_confidence_error_rate` currently reads as `0.0` because confidence is unset in the stitched records. Treat this as "not yet calibrated" rather than "fully trustworthy."

## Holdout1000 Generalization Check

To reduce the risk of overfitting our conclusions to the small `eval244` slice, we built a second benchmark:

- `PrimeVul holdout1000`
- `500 vulnerable` + `500 safe`
- sampled from the normalized `train` split
- excludes all ids used in the current `3000`-example SFT training set

Current comparison on `holdout1000`:

| Model | Label Accuracy | Format Pass Rate | Invalid Output Rate | High-Confidence Error Rate | Avg Tokens |
| --- | ---: | ---: | ---: | ---: | ---: |
| Base 0.5B | 0.2920 | 0.6930 | 0.1510 | 0.1700 | 52.0370 |
| SFT 0.5B | 0.4200 | 0.7820 | 0.2010 | 0.0220 | 35.3530 |
| SFT 0.5B (`safe->none`) | 0.4540 | 0.8150 | 0.1620 | 0.0290 | 37.0380 |

What this changes:

- `SFT 0.5B` still generalizes better than `Base 0.5B`.
- The safer SFT cleanup also survives the larger holdout benchmark: `label_accuracy` improves from `0.4200 -> 0.4540`, while `format_pass_rate` rises from `0.7820 -> 0.8150`.
- The held-out benchmark is clearly harder than `eval244`, so it gives us a more conservative estimate of real performance.
- The strongest stable finding remains calibration rather than raw label gain: SFT sharply cuts high-confidence mistakes on the harder benchmark.
- The latest result helps narrow the open question around `false_negative`: the issue is not only model capacity or prompt style, but also supervision cleanliness on safe examples.
- The current verifier conclusion is therefore cautious: a second-stage reviewer is not ruled out, but it needs its own structurally aligned supervision. Right now the recall-heavy verifier acts more like a noisy risk detector than a reliable structured auditor.
- The most promising verifier direction is now clearly failure-driven rather than generic: teach the second-pass reviewer on concrete misses from the main model, then accept only canonical, structurally clean overrides. That path produces a real but still small gain, and it is the first verifier route that improves recall without obviously corrupting specificity.

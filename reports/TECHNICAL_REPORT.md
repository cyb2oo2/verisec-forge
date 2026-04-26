# Technical Report

## Summary

`VeriSec Forge` is a reproducible post-training and benchmarking stack for structured secure-code reasoning. The current system focuses on defensive vulnerability analysis rather than exploit generation: given code, the model must return structured JSON describing whether a vulnerability is present, the likely weakness family, supporting evidence, an explanation, a repair principle, and a confidence score.

The main research goal in the current phase is not only to improve raw label accuracy, but to separate four failure sources that are usually conflated in secure-code LLM evaluations:

- semantic judgment failure
- explanation and evidence mismatch
- output protocol failure
- calibration failure, especially high-confidence mistakes

## Tasks

### Task A: Weakness Identification

Input:
- function- or file-level code snippet

Output:
- `has_vulnerability`
- `vulnerability_type`
- `severity`
- `evidence`
- `explanation`
- `fix_principle`
- `confidence`

### Task B: Secure Fix Ranking

Input:
- vulnerable code plus repair candidates

Output:
- structured choice among repair options
- short explanation of why the selected fix is safer

The current experimental results in this report are concentrated on Task A.

## Data

### Primary Benchmark

- Dataset: `PrimeVul`
- Evaluation split: balanced `eval244`
- Composition: `122 vulnerable` + `122 safe`

### Expanded Held-out Benchmark

- Dataset: `PrimeVul`
- Evaluation split: held-out balanced `holdout1000`
- Composition: `500 vulnerable` + `500 safe`
- Construction: sampled from the normalized `train` split after excluding all ids used in the current `3000`-example SFT training set

### Paired Patch/Diff Benchmark

- Dataset: `PrimeVul`
- Evaluation split: paired balanced `eval1800`
- Composition: vulnerable/fixed counterparts represented as candidate snippets, paired context, or unified diffs
- Purpose: remove the strongest same-source shortcuts and test whether the model can compare a vulnerable revision against its paired repair signal

### Training Data

- SFT training set: balanced secure-code subset derived from `PrimeVul`
- Best current run: `3000` examples with balanced vulnerable and safe samples

### Preference Data

Three secure-code DPO variants were explored:

- hard preference pairs
- calibrated template-aligned pairs
- label-focused, LoRA-only pairs

## Methods

### Base Models

- `Qwen/Qwen2.5-0.5B-Instruct`
- `Qwen/Qwen2.5-1.5B-Instruct`

### Structured Output Protocol

The system uses:

- JSON-first prompting
- schema-first parsing
- tolerant parsing for JSON-like outputs
- second-pass extraction for a subset of malformed generations

This protocol is important enough to count as part of the research contribution rather than a cosmetic engineering detail, because it lets us distinguish benchmark noise from true reasoning failure.

### Verifier and Ensemble Layer

To study whether the dominant `false_negative` errors can be reduced without retraining the main model, the system also supports a verifier layer:

- self-verification on low-confidence safe predictions
- cross-model verifier ensembles that only reconsider safe predictions
- parser- and type-aware acceptance rules before any override is applied

The most important practical lesson so far is that a verifier must be structurally aligned, not just recall-oriented. Generic labels such as `vulnerable` or `defensive-security-vulnerability` are not specific enough to safely override the main model.

### Best Current Training Recipe

The strongest model so far is:

- balanced `PrimeVul`
- completion-only SFT
- tolerant parser

Checkpoint:
- `checkpoints/sft_secure_code_primevul_qwen05b_balanced_lossfix`

The current best variant adds one small supervision cleanup:

- canonicalize safe examples to `vulnerability_type = none`
- keep completion-only SFT and the same tolerant parser

Checkpoint:
- `checkpoints/sft_secure_code_primevul_qwen05b_balanced_safe_none_only_v1`

## Evaluation Metrics

The current benchmark reports:

- `label_accuracy`
- `format_pass_rate`
- `invalid_output_rate`
- `high_confidence_error_rate`
- `avg_tokens`
- `evidence_support_rate`
- `explanation_support_rate`

## Current Results

### Balanced PrimeVul eval244

| Model | Label Accuracy | Format Pass Rate | Invalid Output Rate | High-Confidence Error Rate | Avg Tokens |
| --- | ---: | ---: | ---: | ---: | ---: |
| Base 0.5B | 0.4098 | 0.5410 | 0.2131 | 0.1639 | 41.8443 |
| SFT 0.5B | 0.4795 | 0.8279 | 0.1598 | 0.0287 | 35.9918 |
| SFT 0.5B (`safe->none`) | 0.4959 | 0.8033 | 0.1516 | 0.0328 | 36.5123 |
| Base 1.5B | 0.0697 | 0.8484 | 0.1311 | 0.1066 | 95.4426 |
| Hard DPO v2 | 0.2090 | 0.3033 | 0.6926 | 0.0205 | 57.6475 |
| Calibrated LoRA-only DPO v1 | 0.3648 | 0.6598 | 0.2910 | 0.0082 | 34.6475 |
| Label-focused LoRA-only DPO v1 | 0.2418 | 0.4549 | 0.2541 | 0.0738 | 30.0738 |

### PrimeVul holdout1000

| Model | Label Accuracy | Format Pass Rate | Invalid Output Rate | High-Confidence Error Rate | Avg Tokens |
| --- | ---: | ---: | ---: | ---: | ---: |
| Base 0.5B | 0.2920 | 0.6930 | 0.1510 | 0.1700 | 52.0370 |
| SFT 0.5B | 0.4200 | 0.7820 | 0.2010 | 0.0220 | 35.3530 |
| SFT 0.5B (`safe->none`) | 0.4540 | 0.8150 | 0.1620 | 0.0290 | 37.0380 |

### PrimeVul same-source presence detector (`Qwen2.5-Coder-1.5B-Instruct`)

To separate "can the model detect vulnerable code?" from "can the model emit a full structured audit record?", we added a pure discriminative `presence-only` detector on `PrimeVul`.

| Model | Presence Accuracy | Vulnerable Recall | Safe Specificity | Precision |
| --- | ---: | ---: | ---: | ---: |
| Classifier 1.5B Coder (LoRA, 3k balanced train) | 0.9524 | 0.9709 | 0.9339 | 0.9363 |

This detector is trained on a balanced `3000`-example subset built from the normalized `PrimeVul` train split after excluding every id used in `secure_code_primevul_holdout_eval_balanced_2000.jsonl`. A direct exact-code-overlap check between the train subset and the held-out eval slice returns `0`, so this result should not be explained away as a trivial duplicate leak.

However, this result is no longer treated as the headline claim. Follow-up shortcut diagnostics show that the same-source holdout is artifact-sensitive: vulnerable and safe examples differ strongly in length, project/source distribution, and other dataset construction artifacts. The threshold sweep is stable on that same distribution, but stability on an artifact-sensitive split is not enough evidence for semantic vulnerability reasoning:

- `threshold = 0.1`: `f1 = 0.9537`, `vulnerable_recall = 0.9810`, `safe_specificity = 0.9239`
- `threshold = 0.5`: `presence_accuracy = 0.9524`, `vulnerable_recall = 0.9709`, `safe_specificity = 0.9339`
- `threshold = 0.9`: `presence_accuracy = 0.9423`, `vulnerable_recall = 0.9429`, `safe_specificity = 0.9418`

The stronger interpretation is diagnostic: narrow discriminative training can exploit the same-source PrimeVul distribution much better than a generative auditor, but the resulting score must be protected by harder paired controls before it can be claimed as secure-code reasoning.

### PrimeVul paired diff reasoning (`Qwen2.5-Coder-1.5B-Instruct`)

The current robust mainline reframes PrimeVul as a paired comparison task. Instead of asking whether an isolated snippet is vulnerable, the model sees candidate-vs-counterpart information and must infer which side carries the vulnerable pattern. This directly tests whether the model uses the repair signal rather than single-snippet artifacts.

| System | Best Balanced Accuracy | Recall | Specificity | F1 | Interpretation |
| --- | ---: | ---: | ---: | ---: | --- |
| same-source detector on paired eval | 0.4961 | 0.1922 | 0.8000 | 0.2761 | same-source shortcut fails under paired evaluation |
| paired-trained snippet detector | 0.5072 | 0.3989 | 0.6156 | 0.4474 | paired labels alone are not enough |
| metadata-only control | 0.5022 | 0.6644 | 0.3400 | 0.5717 | metadata is near chance |
| candidate-only control | 0.5078 | 0.8989 | 0.1167 | 0.6462 | one-sided code remains near chance |
| counterpart-only control | 0.5156 | 0.2011 | 0.8300 | 0.2934 | one-sided repair context remains near chance |
| pair-context detector | 0.6061 | 0.6589 | 0.5533 | 0.6259 | explicit comparison helps |
| candidate+diff detector | 0.6728 | 0.7178 | 0.6278 | 0.6869 | extra context helps but dilutes patch signal |
| diff-only detector, dedup eval | 0.8158 | 0.8022 | 0.8294 | 0.8131 | strongest controlled formulation |

After removing `8` exact/near-duplicate eval rows flagged by train/eval overlap diagnostics, the diff-only result remains stable. Three diff-only seeds on the deduplicated eval set produce a balanced-accuracy mean of `0.8287` and a range of `0.8158-0.8382`. This makes paired diff reasoning the current best-supported PrimeVul result in the repository.

The important shift is conceptual. The project should no longer present the `0.9524` same-source detector score as the main achievement. The stronger claim is that shortcut diagnostics forced a task redesign, and that the redesigned paired diff formulation produces a substantially more credible security-reasoning signal than isolated same-source detection.

### PrimeVul detector + evidence confirmer

To test the next systems hypothesis directly, we trained a narrow `evidence confirmer` rather than another full auditor. The workflow is:

1. run the `PrimeVul presence-only detector` at threshold `0.5`
2. keep only detector-positive samples
3. train a second model whose only job is to decide whether the detector alert is concretely supported by code-level evidence
4. if supported, emit a short structured confirmation with evidence; otherwise emit `has_vulnerability=false` and `evidence=[]`

This confirms a different question than the earlier auditor line. It is not trying to rediscover all vulnerabilities from scratch; it is trying to turn detector-positive traffic into either:

- evidence-confirmed positives
- explicitly unsupported alerts

On `secure_code_primevul_holdout_eval_balanced_2000.jsonl`, this detector+confirmer system reaches:

| Metric | Value |
| --- | ---: |
| detector_positive_rate | 0.5185 |
| confirmer_positive_rate | 0.2094 |
| unsupported_positive_share | 0.0027 |
| avg_evidence_items_per_positive | 1.5294 |
| presence_accuracy | 0.6892 |
| vulnerable_recall | 0.3987 |
| safe_specificity | 0.9798 |
| precision | 0.9519 |
| F1 | 0.5620 |

This is the first positive evidence-grounding result in the repo that does not immediately collapse under a stricter gate. It does not outperform the raw detector on recall, and it is not meant to. Its contribution is different: it converts a very broad, very high-recall detector into a much narrower positive path with extremely high precision and almost no unsupported positives. In other words, this is the first result that actually behaves like an `evidence confirmer` rather than a verbose second auditor.

We also swept the detector threshold while keeping the same confirmer checkpoint fixed:

| Detector Threshold | Detector Positive Rate | Confirmer Positive Rate | Unsupported Positive Share | Presence Accuracy | Vulnerable Recall | Safe Specificity | Precision | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `0.2` | 0.5252 | 0.2122 | 0.0026 | 0.6876 | 0.3998 | 0.9754 | 0.9420 | 0.5613 |
| `0.5` | 0.5185 | 0.2094 | 0.0027 | 0.6892 | 0.3987 | 0.9798 | 0.9519 | 0.5620 |
| `0.8` | 0.5078 | 0.2055 | 0.0027 | 0.6909 | 0.3964 | 0.9854 | 0.9646 | 0.5619 |

This operating-point readout is informative in a different way than the earlier `CodeXGLUE` threshold curves. On `PrimeVul`, once the confirmer is inserted, changing the detector threshold only weakly changes the final system behavior. The positive path becomes mostly confirmer-limited rather than detector-limited. That is a useful systems diagnosis: the next gains are more likely to come from improving evidence confirmation than from endlessly retuning the detector threshold.

We then tried several follow-up generative confirmer variants:

- hard-negative weighting
- supported-positive shaping
- family-aware richer evidence targets

All three underperformed the original confirmer anchor. The strongest of those follow-ups still lagged noticeably behind the first `t=0.5` confirmer, while the most aggressive hard-negative version collapsed into an almost-always-rejecting reviewer. That negative result is useful: the remaining bottleneck is not easily fixed by more generative target shaping alone.

### PrimeVul detector + support scorer

The next step was to narrow the second stage even further and remove free-form generation from the confirmation decision. Instead of asking a second model to emit a structured audit record, we trained a non-generative `support scorer` on detector-positive traffic only. Its job is simply to decide whether a detector alert is supported.

On the same `secure_code_primevul_holdout_eval_balanced_2000.jsonl`, the resulting two-stage system is much stronger than the generative confirmer family:

| Metric | Value |
| --- | ---: |
| detector_positive_rate | 0.5185 |
| scorer_positive_rate | 0.4899 |
| unsupported_positive_share | 0.0640 |
| presence_accuracy | 0.9272 |
| vulnerable_recall | 0.9171 |
| safe_specificity | 0.9373 |
| precision | 0.9360 |
| F1 | 0.9265 |

This is a qualitatively different outcome from the generative confirmer family. The second stage no longer collapses recall, and the overall system now preserves both high recall and high precision. However, the follow-up ablation below shows that this scorer is not an end-to-end improvement over detector-only.

Sweeping the detector threshold around that scorer gives a clear operating-point family:

| Detector Threshold | Detector Positive Rate | Scorer Positive Rate | Unsupported Positive Share | Presence Accuracy | Vulnerable Recall | Safe Specificity | Precision | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `0.2` | 0.5252 | 0.3432 | 0.0750 | 0.7917 | 0.6349 | 0.9485 | 0.9250 | 0.7530 |
| `0.5` | 0.5185 | 0.4899 | 0.0640 | 0.9272 | 0.9171 | 0.9373 | 0.9360 | 0.9265 |
| `0.8` | 0.5078 | 0.1232 | 0.1364 | 0.5896 | 0.2128 | 0.9664 | 0.8636 | 0.3414 |

Unlike the flatter generative-confirmer family, the scorer family has a strong best point. `0.5` is the clear default operating point; `0.2` remains a viable recall-favoring triage mode; and `0.8` is too conservative to be attractive.

The ablation result is important and changes the safe claim. Detector-only / probability pass-through reaches `presence_accuracy = 0.9524`, `vulnerable_recall = 0.9709`, `safe_specificity = 0.9339`, `precision = 0.9363`, and `f1 = 0.9533`, which is stronger than the full support scorer. The current support scorer should therefore be treated as a diagnostic filtering interface, not as the source of the PrimeVul performance gain.

### CodeXGLUE defect detection (`Qwen2.5-Coder-1.5B-Instruct`)

To test whether the low-recall pattern on `PrimeVul` was mainly caused by long, realistic code and label complexity, we added a shorter function-level benchmark line using `CodeXGLUE defect detection`.

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
| Classifier 1.5B Coder (LoRA, 12k) | 0.579 | 0.490 | 0.668 | 0.579 | n/a | n/a | n/a |
| Classifier 1.5B Coder (LoRA, full-balanced 20k) | 0.609 | 0.534 | 0.684 | 0.609 | n/a | n/a | n/a |
| Detector + Support Scorer (holdout2000 best accuracy grid point) | 0.6055 | 0.4800 | 0.7310 | 0.6055 | n/a | n/a | n/a |
| Hybrid (`classifier detect` + `evidence_only audit`) | 0.567 | 0.492 | 0.642 | 0.567 | 1.000 | 0.000 | 0.000* |

The classifier and hybrid rows are the strongest control results in the entire `CodeXGLUE` branch. They show that the current bottleneck is not simply model scale or benchmark fit: under the same data and base model, a discriminative detector can maintain much stronger recall than any of the generative JSON auditors.

More importantly, the detector branch is now showing a real data-scale curve. Moving from `6k -> 12k` balanced classifier supervision raises the default operating point from `0.567 -> 0.579` presence accuracy while also improving safe specificity (`0.642 -> 0.668`) and precision (`0.5788 -> 0.5961`) without giving up vulnerable recall. Scaling again to the full balanced train pool (`20,036` examples) pushes the same checkpoint family further to `presence_accuracy = 0.609`, `vulnerable_recall = 0.534`, `safe_specificity = 0.684`, and `precision = 0.6282`. That is the strongest sign so far in this repo that the classifier path is still meaningfully undertrained rather than already architecture-limited.

Threshold sweeps on the classifier make this even clearer. The detector has at least three practically useful operating points on the same balanced `eval1000`:

- `threshold = 0.2`: recall-heavy triage (`vulnerable_recall = 0.956`, `safe_specificity = 0.098`)
- `threshold = 0.5`: balanced review (`vulnerable_recall = 0.488`, `safe_specificity = 0.642`)
- `threshold = 0.8`: conservative trustworthy mode (`vulnerable_recall = 0.188`, `safe_specificity = 0.974`)

With the full-balanced detector, those operating points get stronger rather than flatter. At `threshold = 0.4`, the detector reaches `presence_accuracy = 0.630`; at `threshold = 0.3`, it reaches `f1 = 0.6869` with `vulnerable_recall = 0.926`. The tradeoff is still real, but now it is a better tradeoff family than before: the detector can supply both a stronger balanced mode and a stronger triage mode from one model.

That detector-only conclusion also survives a larger held-out check. On `secure_code_codexglue_holdout_eval_balanced_2000.jsonl`, the same full-balanced checkpoint reaches `presence_accuracy = 0.6135`, `vulnerable_recall = 0.530`, `safe_specificity = 0.697`, and `precision = 0.6363` at the default `0.5` threshold. Its best held-out `f1 = 0.6741` still appears at `threshold = 0.3`, which means the operating-point story is not just an artifact of `eval1000`: the detector branch is now behaving like a real benchmark-facing line rather than a one-slice optimization.

When we stitch those thresholded detector outputs back into hybrid records, the same detection tradeoff is preserved while `format_pass_rate` remains `1.0`. This means the repo now supports a real systems interpretation: the detector can be tuned for the deployment goal, and the auditor can remain a stable structured-output layer on top. At the same time, the new operating-point diagnostics show the next clear limit of the design: classifier-positive cases still have `unsupported_positive_share = 1.0`, which means the hybrid is producing clean structured records without yet adding concrete auditor-backed evidence spans to positive detections.

We also ported the non-generative support scorer idea from `PrimeVul` to `CodeXGLUE`. The result is useful, but it is not a second benchmark win. On `holdout2000`, the default `detector=0.5, scorer=0.5` point reaches `presence_accuracy = 0.5690`, `vulnerable_recall = 0.3030`, `safe_specificity = 0.8350`, and `precision = 0.6474`. A two-dimensional threshold grid finds the best balanced point at `detector=0.5, scorer=0.2`, with `presence_accuracy = 0.6055`, `vulnerable_recall = 0.4800`, `safe_specificity = 0.7310`, `precision = 0.6409`, and `f1 = 0.5489`.

That is close to the detector-only default result, but it does not beat it. The CodeXGLUE scorer is therefore best interpreted as a policy or confirmation layer rather than as a detector upgrade. This cross-benchmark contrast is important: on `PrimeVul`, supported-vs-unsupported positive traffic is a meaningful second-stage task; on `CodeXGLUE`, the scorer mostly trades recall for specificity.

The best scorer point also tells us where the remaining errors come from. At `detector=0.5, scorer=0.2`, `470` vulnerable examples are missed by the detector before the scorer can act, while only `50` vulnerable examples are detector-positive but rejected by the scorer. In other words, `90.38%` of false negatives are detector misses. That makes the next `CodeXGLUE` training target fairly unambiguous: improve detector discrimination first, then use the scorer as a policy layer.

With the new `12k` detector run, that systems reading becomes even sharper. The practical bottleneck is no longer "can we make a slightly better JSON auditor?" but "how far can we push the detector toward a real benchmark-grade vulnerability filter before we reintroduce the auditor as a narrower evidence confirmer?" That is now the most promising mainline.

## Failure Analysis

### Main Patterns

- `Base 0.5B` is dominated by `false_negative` errors and poor calibration when confidence is high.
- `SFT 0.5B` keeps `false_negative` as the main semantic error, but sharply improves protocol stability and reduces high-confidence mistakes.
- A small supervision cleanup improves the SFT anchor further: forcing safe rows to use `vulnerability_type = none` reduces raw false negatives while preserving most of the calibration gains from the original SFT recipe.
- `Base 1.5B` fails very differently: it is dominated by `false_positive` errors and long, overconfident vulnerability narratives on safe code.
- All DPO variants explored so far underperform the SFT anchor. Full-model DPO tends to collapse into `hard_fail` formatting errors, while LoRA-only DPO is safer but still degrades semantic performance.

### Research Interpretation

These results suggest three early conclusions:

### Current PrimeVul Readout

The PrimeVul interpretation has changed after the paired-split diagnostics. The same-source detector score (`presence_accuracy = 0.9524`, `f1 = 0.9533`) should be treated as an artifact-sensitive diagnostic result, not as the headline secure-code reasoning claim.

The current headline is paired diff reasoning: the diff-only detector reaches `0.8158` best balanced accuracy on the deduplicated paired eval set, and three deduplicated diff-only seeds remain stable in the `0.8158-0.8382` range with mean `0.8287`. Metadata-only, candidate-only, and counterpart-only controls stay near chance, so the paired diff gain is not explained by simple metadata leakage or one-sided snippet artifacts.

The practical conclusion is therefore narrower and stronger: same-source detection is useful for diagnosing dataset shortcuts, while paired diff evaluation is the current robust PrimeVul mainline.

1. Completion-only SFT is a strong and reliable baseline for structured secure-code reasoning.
2. Larger zero-shot models can look more security-fluent while being less trustworthy, especially through over-detection and poor calibration.
3. Preference optimization in this setting is fragile: unless the output protocol is explicitly protected, DPO can damage both structure and judgment.
4. The smaller `eval244` slice was directionally correct, but the larger `holdout1000` benchmark is meaningfully harder and therefore a better generalization check.
5. The remaining `false_negative` problem is partly a supervision hygiene issue. Safe examples that retain concrete CWE labels make the model more conservative; cleaning that signal gives a measurable improvement without the collapse seen in more aggressive recall-focused shaping.
6. The new `PrimeVul presence-only detector` result sharpens that diagnosis. A narrow discriminative objective on the same dataset family reaches `presence_accuracy = 0.9524`, `vulnerable_recall = 0.9709`, and `safe_specificity = 0.9339` on `holdout2000`, with no exact code overlap between the balanced train subset and the holdout slice. That makes it much harder to argue that the earlier PrimeVul failures were driven mainly by raw vulnerability semantics. The stronger explanation is that "detect + classify + explain + evidence + JSON protocol" is simply too much to ask of the small-to-mid generative auditor line.
7. A narrow `PrimeVul detector + evidence confirmer` pipeline is the first result that partially resolves the earlier positive-evidence problem. Starting from the same high-recall detector, the confirmer reduces positive traffic to a much smaller set with `precision = 0.9519`, `safe_specificity = 0.9798`, and `unsupported_positive_share = 0.0027`, while preserving `vulnerable_recall = 0.3987`. That is not a detector replacement; it is evidence that the right second-stage task is confirmation, not full re-auditing.
8. Sweeping the detector threshold on that same pipeline does not radically change the outcome. Across `0.2 / 0.5 / 0.8`, the system stays near `f1 ≈ 0.562` while `unsupported_positive_share` remains near zero. This suggests that the dominant bottleneck in the new PrimeVul two-stage line is no longer detector calibration alone; it is the confirmer's evidence boundary.
9. The next experiment breaks that boundary in an important way: once the second stage is reframed as a non-generative `support scorer`, the same `PrimeVul` detector line reaches `presence_accuracy = 0.9272`, `vulnerable_recall = 0.9171`, `safe_specificity = 0.9373`, and `precision = 0.9360`. This is much stronger than the generative confirmer, but not stronger than detector-only.
10. The scorer ablation sharpens the claim: detector-only / probability pass-through reaches `presence_accuracy = 0.9524` and `f1 = 0.9533`, so the detector is the performance driver. The support scorer is useful as a controlled second-stage interface, but future work must beat detector-only before claiming system-level gain.
11. A `CodeXGLUE` follow-up sharpens that conclusion rather than weakening it. The same non-generative scorer idea does transfer, but mostly as a conservative confirmation layer: it raises specificity and precision, yet still underperforms the detector-only branch on balanced end-to-end detection.
12. On the shorter `CodeXGLUE` benchmark, the main open problem becomes even clearer: the generative structured-output formulation itself appears to push the model toward a conservative safe-biased operating point. This is supported by the discriminative LoRA classifier, which substantially outperforms all generative SFT variants on vulnerable recall.
13. The first practical dual-system result is now in place: a classifier can act as a high-recall detector, while a generative auditor can provide stable machine-readable secure-code records. This hybrid preserves classifier-level detection and achieves perfect output formatting, but the new operating-point diagnostics show that it still lacks evidence-grounded positive confirmations: across thresholds, classifier-positive cases currently have `unsupported_positive_share = 1.0`.
14. A stricter evidence-gated hybrid makes that limitation even clearer. When we require classifier-positive cases to also carry auditor evidence before allowing a vulnerable-path record, both `eval1000` and `holdout2000` collapse to `vulnerable_recall = 0.0`. This is a sharp negative result, but also a useful systems diagnosis: the current auditor is good at structural rendering, not yet at positive-case evidence confirmation.
15. A targeted `detector_positive_auditor` follow-up confirms that this is not solved by simply training the auditor on classifier-positive traffic. On `CodeXGLUE eval1000`, that model drops to `label_accuracy = 0.336`, `format_pass_rate = 0.659`, and `vulnerable_recall = 0.004`, and when stitched back into the hybrid it only reduces `unsupported_positive_share` from `1.0` to about `0.998-0.999`. Under evidence-gated evaluation it again collapses to effectively zero positive traffic. The open problem therefore remains evidence grounding, not threshold tuning or positive-only prompt exposure.
16. By contrast, the detector-only branch continues to improve when we scale the balanced training pool. The jump from `6k -> 12k -> full-balanced 20k` is now monotonic on the default operating point (`0.567 -> 0.579 -> 0.609` presence accuracy), which is the strongest evidence yet that the mainline should shift toward "make the detector first-class, then narrow the auditor" rather than continuing to widen generative auditor objectives.
17. The larger `CodeXGLUE holdout2000` check makes that recommendation more defensible. The same full-balanced detector keeps improving out-of-sample (`presence_accuracy = 0.6135`, `safe_specificity = 0.697`, `precision = 0.6363`) while preserving the same threshold tradeoff shape. So the detector branch now has both an internal scaling curve and an external held-out confirmation, which is much stronger evidence than we ever obtained for the generative auditor line.

### Holdout Generalization Readout

- On the larger held-out benchmark, `SFT 0.5B` still beats `Base 0.5B` on label accuracy (`0.2920 -> 0.4200`).
- The cleaned SFT variant improves that further to `0.4540`, while also improving `format_pass_rate` (`0.7820 -> 0.8150`) relative to the earlier SFT anchor.
- The strongest robustness gain remains calibration: `high_confidence_error_rate` falls from `0.1700` to `0.0220`.
- The dominant semantic error class remains `false_negative`, which means the main unresolved problem is missed vulnerabilities rather than uncontrolled over-detection.
- The held-out benchmark narrows the apparent gap seen on `eval244`, which is useful: it suggests the project now has both an efficient small benchmark and a harder, more realistic generalization check.

### Verifier Readout

- A self-verifier built from the same `0.5B evidence-only` checkpoint does not materially help. It triggers often on low-confidence safe predictions, but never produces a trustworthy override.
- A recall-heavy external verifier (`presence_only_vulnerable`) can flip some safe predictions to vulnerable under a loose policy, but the apparent gain is mostly driven by generic labels rather than canonical `cwe-*` outputs.
- When the ensemble policy is tightened to require canonical `cwe-*` labels, clean formatting, and high parse confidence, those loose overrides disappear entirely.
- A more conservative verifier (`vulnerable_oversample_clean`) survives the strict gate once, which confirms that verifier-style recovery is possible in principle, but current verifier checkpoints are still too weak and too sparse to move the benchmark meaningfully.
- A dedicated verifier-specific SFT checkpoint (`verifier_canonical_v1`) also underlines the same constraint from the opposite direction: it becomes very safe and structurally narrower, but on `eval244` it still only reaches `vulnerable_recall = 0.0246` despite perfect `safe_specificity = 1.0000`.
- A failure-driven verifier built from the main model's own `false_negative` examples changes the picture in a more interesting way. As a standalone verifier it reaches `vulnerable_recall = 0.0574` and `format_pass_rate = 0.8320`, which is meaningfully higher recall than the generic canonical verifier, but it pays for that with `high_confidence_error_rate = 0.2623`.
- When that failure-driven verifier is placed behind a canonical mid-threshold gate, it produces `1` accepted override on `eval244`. The net result is a small but real recall improvement (`vulnerable_recall = 0.0410` versus `0.0328` for the main auditor) while preserving `safe_specificity = 0.9918`, but it still does not lift exact `label_accuracy`.
- A larger failure-driven verifier mined from a broader `seed800` slice does not improve the situation. It keeps the same `label_accuracy = 0.4631`, but `format_pass_rate` falls to `0.4918` and `avg_parse_confidence` drops to `0.4006`. This indicates that simply adding more mined misses does not automatically create a better verifier; the second-pass task still needs stronger structural constraints.
- A compact failure-driven verifier also fails to become trustworthy. Although it shortens outputs substantially (`avg_tokens = 22.6803`) and increases standalone vulnerable recall (`0.1639`), it simultaneously collapses `safe_specificity` to `0.4508` and drives `label_accuracy` down to `0.2254`. This suggests that the verifier problem is not solved by brevity alone; the model still lacks a well-behaved second-pass objective.
- A decision-only failure-driven verifier narrows the task even further: it emits a tiny, fixed-shape JSON object and reaches `label_accuracy = 0.4262`, `vulnerable_recall = 0.0492`, `safe_specificity = 0.8525`, and `format_pass_rate = 0.5984`. This is substantially better than the compact verifier, but still weaker than the default failure-driven verifier and much weaker than the main SFT auditor.
- Placed behind the same canonical mid-threshold gate, the decision-only verifier is the first verifier route with `2` accepted overrides on `eval244`. However, those extra accepted flips still do not improve secure-code labeling: `label_accuracy` falls to `0.4877`, `safe_specificity` drops from `0.9918` to `0.9754`, and `vulnerable_recall` stays at `0.0328`. The verifier therefore remains a useful analysis tool, but not yet a trustworthy deployment-time recovery module.
- A binary-judge failure-driven verifier goes one step further and removes almost all reviewer freedom. It outputs only a highly constrained vulnerable/not-vulnerable judgment plus a canonical `cwe-*` label when applicable. Standalone, this makes the verifier extremely recall-heavy (`vulnerable_recall = 0.4098`) but also highly unreliable (`safe_specificity = 0.1803`, `label_accuracy = 0.0943`, `high_confidence_error_rate = 0.6025`).
- Even after passing those binary-judge predictions through the same canonical mid-threshold gate, the net benchmark effect remains negative. The ensemble accepts `9` overrides on `eval244`, which raises `vulnerable_recall` to `0.0492`, but exact `label_accuracy` falls to `0.4672`, `safe_specificity` drops to `0.9344`, and `high_confidence_error_rate` rises to `0.0615`. This makes the verifier result sharper rather than better: the current obstacle is no longer output verbosity or formatting alone, but learning a second-pass decision rule that contributes new evidence rather than simply a stronger vulnerable prior.
- A label-only failure-driven verifier narrows the task one step further toward a reranker-style judgment. It omits evidence entirely, uses fixed lightweight explanations, and only learns whether a safe prediction should be overturned plus a canonical label. Standalone, this is much cleaner than the binary-judge model (`label_accuracy = 0.1885`, `vulnerable_recall = 0.2787`, `safe_specificity = 0.3770`, `format_pass_rate = 0.8197`, `high_confidence_error_rate = 0.1230`), but under the same strict canonical gate it produces `0` accepted overrides. So the result is still negative, but in a useful way: a tidier second-pass model is easier to trust structurally, yet still fails to contribute enough specific new signal to beat the main auditor.
- The verifier experiments therefore reinforce the main project thesis: trustworthy secure-code reasoning is not only about recall, but about whether the model can express risk judgments in a structurally reliable, evaluable form.
- Taken together, the verifier branch now supports a fairly strong negative result: across generic canonical reviewers, failure-driven reviewers, compact reviewers, decision-only reviewers, binary-judge reviewers, and label-only rerankers, we can reliably trade off recall against specificity and calibration, but we have not yet found a second-pass model that improves the main SFT auditor on exact secure-code labeling under a trustworthy acceptance rule.

## Practical Conclusion

At the current stage, the most defensible claim is not that secure-code DPO is solved, but that the project has established a clean benchmark-and-analysis loop:

- a real secure-code dataset
- a structured output protocol
- parser-aware evaluation
- failure taxonomy with semantic, protocol, and calibration breakdowns
- a strong SFT anchor that future methods must beat
- a stronger, cleaner SFT anchor that explicitly removes spurious CWE labels from safe supervision
- a larger held-out benchmark that prevents over-claiming from a small evaluation slice
- an initial verifier framework that shows how recall recovery can look promising under loose rules, then disappear under stricter canonical acceptance rules
- a failure-driven verifier route that demonstrates how main-model misses can be turned into targeted second-pass supervision, even though the current gains remain modest under strict acceptance
- a second benchmark line (`CodeXGLUE`) showing that better data-model fit helps, but does not by itself remove the recall/calibration tradeoff in generative structured auditing
- a classifier-vs-auditor comparison that demonstrates the main current systems lesson: the repo's strongest practical path is no longer a single model, but a detector-plus-auditor split
- a shortcut-aware PrimeVul result showing that the best current secure-code path is paired diff reasoning, with same-source detector scores treated as artifact-sensitive diagnostics rather than headline claims

*For the current hybrid row, `high_confidence_error_rate = 0.000` should be read as "not yet calibrated" rather than "perfect confidence behavior", because the stitched hybrid records currently leave confidence unset.

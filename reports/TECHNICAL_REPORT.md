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
| Hybrid (`classifier detect` + `evidence_only audit`) | 0.567 | 0.492 | 0.642 | 0.567 | 1.000 | 0.000 | 0.000* |

The classifier and hybrid rows are the strongest control results in the entire `CodeXGLUE` branch. They show that the current bottleneck is not simply model scale or benchmark fit: under the same data and base model, a discriminative detector can maintain much stronger recall than any of the generative JSON auditors.

Threshold sweeps on the classifier make this even clearer. The detector has at least three practically useful operating points on the same balanced `eval1000`:

- `threshold = 0.2`: recall-heavy triage (`vulnerable_recall = 0.956`, `safe_specificity = 0.098`)
- `threshold = 0.5`: balanced review (`vulnerable_recall = 0.488`, `safe_specificity = 0.642`)
- `threshold = 0.8`: conservative trustworthy mode (`vulnerable_recall = 0.188`, `safe_specificity = 0.974`)

When we stitch those thresholded detector outputs back into hybrid records, the same detection tradeoff is preserved while `format_pass_rate` remains `1.0`. This means the repo now supports a real systems interpretation: the detector can be tuned for the deployment goal, and the auditor can remain a stable structured-output layer on top.

## Failure Analysis

### Main Patterns

- `Base 0.5B` is dominated by `false_negative` errors and poor calibration when confidence is high.
- `SFT 0.5B` keeps `false_negative` as the main semantic error, but sharply improves protocol stability and reduces high-confidence mistakes.
- A small supervision cleanup improves the SFT anchor further: forcing safe rows to use `vulnerability_type = none` reduces raw false negatives while preserving most of the calibration gains from the original SFT recipe.
- `Base 1.5B` fails very differently: it is dominated by `false_positive` errors and long, overconfident vulnerability narratives on safe code.
- All DPO variants explored so far underperform the SFT anchor. Full-model DPO tends to collapse into `hard_fail` formatting errors, while LoRA-only DPO is safer but still degrades semantic performance.

### Research Interpretation

These results suggest three early conclusions:

1. Completion-only SFT is a strong and reliable baseline for structured secure-code reasoning.
2. Larger zero-shot models can look more security-fluent while being less trustworthy, especially through over-detection and poor calibration.
3. Preference optimization in this setting is fragile: unless the output protocol is explicitly protected, DPO can damage both structure and judgment.
4. The smaller `eval244` slice was directionally correct, but the larger `holdout1000` benchmark is meaningfully harder and therefore a better generalization check.
5. The remaining `false_negative` problem is partly a supervision hygiene issue. Safe examples that retain concrete CWE labels make the model more conservative; cleaning that signal gives a measurable improvement without the collapse seen in more aggressive recall-focused shaping.
6. On the shorter `CodeXGLUE` benchmark, the main open problem becomes even clearer: the generative structured-output formulation itself appears to push the model toward a conservative safe-biased operating point. This is supported by the discriminative LoRA classifier, which substantially outperforms all generative SFT variants on vulnerable recall.
7. The first practical dual-system result is now in place: a classifier can act as a high-recall detector, while a generative auditor can provide stable machine-readable secure-code records. This hybrid preserves classifier-level detection and achieves perfect output formatting, but it still inherits the classifier's precision/specificity tradeoff and often lacks strong evidence spans.

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

*For the current hybrid row, `high_confidence_error_rate = 0.000` should be read as "not yet calibrated" rather than "perfect confidence behavior", because the stitched hybrid records currently leave confidence unset.

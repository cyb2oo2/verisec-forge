# Base to GRPO Comparison

| Stage | Accuracy | Format Pass Rate | Avg Tokens | Second-Pass Parse Rate | Low-Confidence Trigger Rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| Base (`Qwen/Qwen2.5-0.5B-Instruct`) | 0.80 | 1.00 | 14.2 | 0.20 | 0.20 |
| SFT (`checkpoints/sft`) | 1.00 | 1.00 | 8.2 | 0.00 | 0.00 |
| DPO (`checkpoints/dpo`) | 1.00 | 1.00 | 8.2 | 0.00 | 0.00 |
| GRPO (`checkpoints/grpo`) | 1.00 | 1.00 | 7.8 | 0.00 | 0.00 |

## Notes

- The base model already benefits from JSON-first prompting, schema-first parsing, and low-confidence second-pass extraction, but it still misses one reasoning example on the fixed math eval set.
- SFT is the biggest jump in this v1 run: it removes the remaining reasoning error and also reduces average output length substantially.
- DPO preserves the SFT gains on this tiny eval set but does not add a visible accuracy gain yet.
- GRPO now runs with non-zero rewards and keeps accuracy at 1.00 while making answers slightly shorter on average than SFT/DPO.
- Because the eval set has only 5 examples, these results are useful for pipeline validation and failure analysis, but not yet strong enough for broad claims.

# GSM8K Real-Data SFT Ablation

| Stage | Accuracy | Format Pass Rate | Avg Tokens | Second-Pass Parse Rate |
| --- | ---: | ---: | ---: | ---: |
| Base (`Qwen2.5-0.5B-Instruct`) | 0.10 | 0.80 | 25.49 | 0.30 |
| `0.5B + GSM8K full SFT (7473)` | 0.32 | 0.82 | 57.43 | 0.18 |
| Base (`Qwen2.5-1.5B-Instruct`) | 0.38 | 0.38 | 58.89 | 0.62 |
| `1.5B + GSM8K SFT (2000)` | 0.49 | 0.26 | 45.42 | 0.74 |
| `1.5B + GSM8K SFT (5000)` | 0.46 | 0.60 | 36.95 | 0.40 |
| `1.5B + GSM8K full SFT (7473)` | 0.43 | 0.47 | 39.67 | 0.53 |

## GSM8K Notes

- Model capacity is the biggest single lever so far: the `1.5B` base model already beats the `0.5B` full-SFT model on the same GSM8K dev100 slice.
- Real-data SFT does improve correctness, but the best point is not monotonic with data size in this setup. The current peak is the `1.5B + 2000` run at `49%`.
- The `5000`-example run is the best compromise so far between correctness and protocol stability. It is slightly below the `2000` run on accuracy, but much better on `format_pass_rate` and less dependent on second-pass recovery.
- Full `7473`-example SFT currently underperforms the `5000` midpoint, which suggests that target style drift or overfitting to noisier reasoning traces is offsetting some of the gains from more supervision.
- For the next round, the best bet is to keep the `1.5B` model and clean or shorten the target reasoning further before moving on to DPO.

# PrimeVul Secure-Code Comparison

| Stage | Label Accuracy | Format Pass Rate | High-Confidence Error Rate | Avg Tokens | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| Base (`Qwen2.5-0.5B-Instruct`) | 0.4098 | 0.5410 | 0.1639 | 41.84 | Balanced `eval244`, parser-aware secure-code baseline |
| SFT (`0.5B + balanced PrimeVul + completion-only loss`) | 0.4795 | 0.8279 | 0.0246 | 35.99 | Earlier best SFT anchor |
| SFT (`0.5B + safe->none canonicalization + completion-only loss`) | 0.4959 | 0.8033 | 0.0328 | 36.51 | Current best `eval244` secure-code model; reduces false negatives from `79` to `72` |
| DPO (`0.5B + PrimeVul SFT checkpoint + preference pairs`) | 0.4795 | 0.8279 | 0.0287 | 36.23 | Historical run; later found to be implementation-contaminated by frozen merged weights |
| Hard DPO v2 (`0.5B + hard preference pairs + unfrozen merged model`) | 0.2090 | 0.3033 | 0.0205 | 57.65 | Real training run; collapsed into malformed verbose outputs |
| Calibrated DPO v1 (`0.5B + template-aligned preference pairs + full-model updates`) | 0.0328 | 0.0205 | 0.0205 | 26.21 | Catastrophic format collapse despite cleaner preference formatting |
| Calibrated LoRA-only DPO v1 (`0.5B + template-aligned preference pairs + adapter-only updates`) | 0.3648 | 0.6598 | 0.0082 | 34.65 | First non-catastrophic DPO result; preserves more structure but still trails SFT |
| Label-focused LoRA-only DPO v1 (`0.5B + label-anchored preference pairs + adapter-only updates`) | 0.2418 | 0.4549 | 0.0738 | 30.07 | More conservative label/CWE-focused preference shaping, but still regresses well below SFT |
| Base (`Qwen2.5-1.5B-Instruct`) | 0.0697 | 0.8484 | 0.1066 | 95.44 | Strong over-detection bias on secure-code prompts |
| Failure-driven verifier SFT (`0.5B + second-pass SFT on real false negatives`) | 0.4631 | 0.8320 | 0.2623 | 32.34 | Better vulnerable recall as a standalone verifier, but too many confident mistakes to replace the main SFT auditor |
| Failure-driven verifier SFT (`0.5B + larger seed800 mined false negatives`) | 0.4631 | 0.4918 | 0.0984 | 47.28 | More mined failures did not stabilize the verifier; protocol quality regressed sharply |
| Failure-driven compact verifier (`0.5B + short JSON verifier target`) | 0.2254 | 0.3525 | 0.2746 | 22.68 | Shorter output alone does not help; recall rises but specificity and exact labeling collapse |
| Failure-driven decision-only verifier (`0.5B + tiny fixed-shape verifier target`) | 0.4262 | 0.5984 | 0.1434 | 20.18 | Narrower than compact and more stable, but still clearly weaker than the main SFT auditor |
| Failure-driven binary-judge verifier (`0.5B + binary second-pass judge target`) | 0.0943 | 0.7500 | 0.6025 | 21.67 | Extremely recall-heavy as a standalone verifier, but catastrophically over-sensitive and overconfident |
| Failure-driven label-only verifier (`0.5B + label-only second-pass target`) | 0.1885 | 0.8197 | 0.1230 | 16.29 | Cleaner and shorter than binary-judge, but still too over-sensitive to trust as a standalone verifier |
| PrimeVul Presence-only Detector (`1.5B Coder seq-cls LoRA, 3k`) | 0.9524 | n/a | n/a | n/a | Presence-only detector on `PrimeVul holdout2000`; `vulnerable_recall = 0.9709`, `safe_specificity = 0.9339`, exact code overlap with train subset checked as `0` |
| PrimeVul Detector + Evidence Confirmer (`1.5B Coder cls + 1.5B Coder confirmer`) | 0.6892 | n/a | n/a | n/a | First non-trivial evidence-confirmed positive path on `PrimeVul holdout2000`; `vulnerable_recall = 0.3987`, `safe_specificity = 0.9798`, `precision = 0.9519`, `unsupported_positive_share = 0.0027` |
| PrimeVul Detector + Support Scorer (`1.5B Coder cls + 1.5B Coder scorer`) | 0.9272 | n/a | n/a | n/a | Diagnostic two-stage system on `holdout2000`; useful as a filter interface but below detector-only; `vulnerable_recall = 0.9171`, `safe_specificity = 0.9373`, `precision = 0.9360`, `f1 = 0.9265` |

## PrimeVul Notes

- The most important secure-code result so far is the `0.5B` jump from `0.4098 -> 0.4795` on balanced `PrimeVul eval244`, while also improving `format_pass_rate` from `0.5410 -> 0.8279`.
- The `completion-only` SFT fix was decisive. Earlier secure-code SFT runs were misleading because prompt tokens dominated the loss on long code snippets.
- The tolerant parser is part of the real engineering result, not a cosmetic add-on. It lets us measure reasoning quality separately from protocol breakage.
- The first DPO checkpoint originally looked valid, but later debugging showed the merged SFT model was frozen during DPO, so those early checkpoints were effectively unchanged copies. After fixing `training_dpo.py` to unfreeze merged parameters, the original easy-preference conclusion should be treated as implementation-contaminated rather than final.
- The corrected hard-DPO run is a real negative result: harder preference pairs plus full-model updates did not improve secure-code reasoning, and instead pushed the model toward verbose malformed outputs with `format_pass_rate = 0.3033` and `label_accuracy = 0.2090`.
- Simply making preference pairs more template-aligned was not enough when we still allowed full-model DPO updates. `calibrated_v1` collapsed even harder, which suggests the update regime itself was destabilizing the SFT protocol, not just the pair quality.
- Switching to LoRA-only DPO is the first sign that we can push preference learning without totally destroying structured output. `calibrated_lora_v1` keeps `format_pass_rate = 0.6598`, far above the full-model DPO runs, but it still does not beat the SFT anchor on either accuracy or protocol stability.
- Tightening preference construction even further around `has_vulnerability`, `vulnerability_type`, and `confidence` did not rescue DPO in this setup. `label_focused_lora_v1` trained cleanly, but it still regressed to `label_accuracy = 0.2418` with `format_pass_rate = 0.4549`, which suggests we are still over-optimizing preference noise relative to the much stronger SFT anchor.
- The current practical conclusion is that SFT remains the strongest secure-code model. DPO is not ruled out, but future runs should preserve the SFT template more aggressively and restrict preference learning to low-entropy decisions such as `has_vulnerability`, `vulnerability_type`, and calibration fields.
- `1.5B` zero-shot underperformed badly, not because the model is weaker in general, but because it over-predicts vulnerabilities and produces long, security-flavored rationales for many safe samples.
- That failure mode is useful research signal for trustworthy secure-code reasoning: larger unaligned models can look more expert while being less calibrated.
- A failure-driven verifier trained on real `false_negative` cases is the first verifier-specific route that materially increases standalone vulnerable recall beyond the generic canonical verifier. However, it also raises high-confidence error sharply, so its best role is still as a gated second-pass model rather than as a new primary auditor.
- Under a canonical mid-threshold ensemble gate, the failure-driven verifier produces `1` accepted override. That small result is still useful: it shows the failure-driven route carries some recoverable signal even after we require clean `cwe-*` outputs.
- Scaling that same verifier recipe to a larger mined failure set (`seed800`) does not solve the core problem. The verifier still does not beat the main SFT auditor, and its format stability drops sharply, which points to task formulation rather than raw mined-data volume as the limiting factor.
- Making the verifier output shorter is also not enough. The compact verifier is fast and terse, but it becomes far too eager to flag vulnerabilities and still produces many malformed outputs, so it is not a practical path to a trustworthy second-pass reviewer.
- Pushing the verifier all the way to a decision-only target is a cleaner negative result. It is more stable than the compact verifier and is the first route that yields `2` accepted canonical overrides under the mid-threshold ensemble gate, but those extra overrides still do not improve vulnerable recall and instead slightly reduce exact label accuracy and specificity.
- We also tested that binary-judge objective directly. It makes the verifier much more willing to overturn safe predictions, but without a better second-pass decision boundary that extra decisiveness mostly turns into false positives.
- The label-only reranker-style verifier completes that picture. It is the cleanest standalone failure-driven verifier so far in terms of output length and structure, but once we force the same canonical mid-threshold acceptance rule it contributes `0` accepted overrides.
- In practical terms, this means the verifier story is now coherent across variants: every time we narrow generation freedom, we improve one dimension of control, but we still fail to create a second-pass model that beats the main SFT auditor under a trustworthy gate.
- A first `PrimeVul detector + evidence confirmer` pipeline gives us the missing middle step between "high-recall detector" and "full structured auditor". Starting from the `presence-only detector` at threshold `0.5`, the confirmer filters positive traffic down to a smaller set with `precision = 0.9519`, `safe_specificity = 0.9798`, and `unsupported_positive_share = 0.0027`, while still keeping `vulnerable_recall = 0.3987`.
- Sweeping the detector threshold on top of that confirmer gives a surprisingly flat family of operating points on `PrimeVul holdout2000`. Across `0.2 / 0.5 / 0.8`, the system stays around `f1 ~ 0.562`, `unsupported_positive_share ~ 0.0026-0.0027`, and `avg_evidence_items_per_positive ~ 1.53`. That means the two-stage system is no longer mainly controlled by the detector threshold; the confirmer itself is now the dominant boundary on the final positive path.
- Additional generative confirmer ablations did not improve that picture. Hard-negative weighting, supported-positive shaping, and family-aware richer targets all underperformed the original confirmer anchor, which suggests the remaining limiter is not easily fixed by reweighting or more elaborate text supervision.
- The non-generative `PrimeVul detector + support scorer` line reaches `presence_accuracy = 0.9272`, `vulnerable_recall = 0.9171`, `safe_specificity = 0.9373`, `precision = 0.9360`, and `f1 = 0.9265`.
- The follow-up ablation changes the project diagnosis in a useful way: detector-only / probability pass-through is stronger (`presence_accuracy = 0.9524`, `f1 = 0.9533`), so the detector is the current performance driver. The support scorer remains useful as a controlled second-stage interface, but not as an end-to-end improvement yet.

# PrimeVul Holdout1000 Expansion

To reduce the risk that the small `eval244` slice was flattering or unstable, we built a larger held-out balanced benchmark from the `PrimeVul` train split after excluding all ids used in the current `3000`-example SFT training set.

- Benchmark: `secure_code_primevul_holdout_eval_balanced_1000.jsonl`
- Composition: `500 vulnerable` + `500 safe`
- Overlap with current SFT train set: `0 ids`

| Stage | Label Accuracy | Format Pass Rate | Invalid Output Rate | High-Confidence Error Rate | Avg Tokens | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Base (`Qwen2.5-0.5B-Instruct`) | 0.2920 | 0.6930 | 0.1510 | 0.1700 | 52.04 | Larger held-out benchmark, substantially harder than `eval244` |
| SFT (`0.5B + balanced PrimeVul + completion-only loss`) | 0.4200 | 0.7820 | 0.2010 | 0.0220 | 35.35 | Earlier best generalization result on the larger holdout |
| SFT (`0.5B + safe->none canonicalization + completion-only loss`) | 0.4540 | 0.8150 | 0.1620 | 0.0290 | 37.04 | Current best holdout result; preserves calibration gains while improving recall |

## Holdout1000 Notes

- The larger held-out benchmark confirms that the `SFT` recipe still beats the `Base` model on label accuracy (`0.2920 -> 0.4200`) and sharply reduces high-confidence mistakes (`0.1700 -> 0.0220`).
- A smaller, more surgical target cleanup improved the SFT anchor further. Canonicalizing safe samples to `vulnerability_type = none` lifts held-out accuracy from `0.4200 -> 0.4540` while keeping `high_confidence_error_rate` low (`0.0290`).
- The margin is smaller than on `eval244`, which suggests the original balanced eval slice was directionally correct but somewhat easier than a larger held-out sample.
- The dominant semantic failure for both models on the larger holdout is still `false_negative`, which means the main open problem is missed vulnerabilities rather than uncontrolled over-detection.
- The best current checkpoint is now the safer-cleanup SFT variant. It improves recall without the collapse we saw in the earlier recall-focused experiment, which suggests the real issue was label canonicalization noise rather than a need for more aggressive confidence shaping.
- A new `PrimeVul presence-only detector` line changes the interpretation of the whole benchmark branch. With `1.5B Coder + LoRA sequence classification` on a balanced `3000`-example train subset and evaluation on `holdout2000`, the model reaches `presence_accuracy = 0.9524`, `vulnerable_recall = 0.9709`, and `safe_specificity = 0.9339`. Because the train subset was built by excluding holdout ids and exact code overlap checks are `0`, this is strong evidence that the hardest part of the earlier PrimeVul pipeline was not raw vulnerable-vs-safe discrimination, but the structured generative auditing objective layered on top of it.
- A first `PrimeVul detector + evidence confirmer` pipeline then gave us the missing middle step between "high-recall detector" and "full structured auditor". Starting from the `presence-only detector` at threshold `0.5`, the confirmer filters positive traffic down to a smaller set with `precision = 0.9519`, `safe_specificity = 0.9798`, and `unsupported_positive_share = 0.0027`, while still keeping `vulnerable_recall = 0.3987`.
- The newest ablation makes the result more conservative: a `PrimeVul detector + support scorer` line reaches `presence_accuracy = 0.9272`, but detector-only / probability pass-through reaches `presence_accuracy = 0.9524`. That means the best current PrimeVul component is the detector, not the scorer.

# CodeXGLUE Coder-1.5B Comparison

To test whether the low-recall behavior was mostly a `PrimeVul` realism/length mismatch, we moved to a shorter function-level binary benchmark:

- Dataset: `CodeXGLUE defect detection`
- Model: `Qwen/Qwen2.5-Coder-1.5B-Instruct`
- Eval slice: `secure_code_codexglue_eval_balanced_1000.jsonl`

| Stage | Presence Accuracy | Vulnerable Recall | Safe Specificity | Label Accuracy | Format Pass Rate | Invalid Output Rate | High-Confidence Error Rate | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Base (`Qwen2.5-Coder-1.5B-Instruct`) | 0.437 | 0.358 | 0.516 | 0.330 | 0.886 | 0.093 | 0.014 | Stronger vulnerable prior, middling calibration and label precision |
| SFT (`safe->none`, 3k) | 0.477 | 0.078 | 0.876 | 0.477 | 0.939 | 0.061 | 0.248 | Much safer and more structured, but extremely conservative |
| SFT (`safe->none`, 6k) | 0.473 | 0.072 | 0.874 | 0.473 | 0.937 | 0.061 | 0.227 | More data alone does not fix low recall |
| SFT (`standard`, 6k) | 0.477 | 0.078 | 0.876 | 0.477 | 0.939 | 0.061 | 0.229 | Nearly identical to `safe->none`; low recall is not just caused by safe canonicalization |
| SFT (`evidence_only`, 6k) | 0.474 | 0.082 | 0.866 | 0.474 | 0.942 | 0.058 | 0.182 | Better evidence fields and lower parser dependence, but still false-negative dominated |
| SFT (`recall_focused`, 6k) | 0.472 | 0.076 | 0.868 | 0.472 | 0.935 | 0.064 | 0.185 | Confidence/wording shaping alone does not recover vulnerable recall |
| SFT (`vulnerable_oversample_clean`, 6k) | 0.482 | 0.138 | 0.826 | 0.482 | 0.940 | 0.059 | 0.405 | Recovers some recall, but mostly by injecting a stronger vulnerable prior and many more confident mistakes |
| Classifier (`sequence classification` LoRA, 6k) | 0.567 | 0.492 | 0.642 | 0.567 | n/a | n/a | n/a | Discriminative control baseline; much stronger recall than any generative JSON route |
| Classifier (`sequence classification` LoRA, 12k) | 0.579 | 0.490 | 0.668 | 0.579 | n/a | n/a | n/a | First clear detector-only data-scale gain; default threshold already improves over 6k |
| Classifier (`sequence classification` LoRA, full-balanced 20k) | 0.609 | 0.534 | 0.684 | 0.609 | n/a | n/a | n/a | Strongest detector-only run so far; continues the data-scale trend and finally clears `0.60` balanced accuracy |
| Detector + Support Scorer (`full-balanced detector`, best accuracy grid point) | 0.606 | 0.480 | 0.731 | 0.606 | n/a | n/a | n/a | Non-generative confirmation layer on `holdout2000`; `detector=0.5`, `scorer=0.2`, close to but below detector-only |
| Hybrid (`classifier detect` + `evidence_only audit`) | 0.567 | 0.492 | 0.642 | 0.567 | 1.000 | 0.000 | 0.000* | Preserves classifier detection while emitting deterministic structured audit records |

## CodeXGLUE Notes

- Moving to a shorter, community-standard function-level benchmark does help the setup behave more like a normal vulnerability detector, which validates the earlier suspicion that long realistic `PrimeVul` code was part of the mismatch.
- But the main tradeoff survives the dataset switch: under this generative structured-output setup, the best SFT recipes still drift toward conservative auditors with low `vulnerable_recall`.
- Scaling the balanced training subset from `3k -> 6k` has almost no effect on recall. That makes it unlikely that the current failure mode is simply "not enough CodeXGLUE data."
- The strongest negative control here is `standard 6k`: once we remove the `safe->none` cleanup, the model still lands almost exactly on the same operating point. So the low-recall regime is not primarily a side effect of safe-label canonicalization.
- `evidence_only` cleans up protocol quality and parser dependence, but it does not change the semantic error shape: the model remains overwhelmingly `false_negative`-dominated.
- `vulnerable_oversample_clean` is the only variant that materially raises recall, but it does so at the cost of a very large jump in `high_confidence_error_rate` (`0.405`). That makes it look more like prior shifting than trustworthy vulnerability discovery.
- The discriminative LoRA classifier is the strongest control in this branch. On the same `eval1000`, it reaches `presence_accuracy = 0.567` and `vulnerable_recall = 0.492`, far above every generative JSON model.
- Scaling that same detector from `6k -> 12k` is the first strong sign that this branch is still data-limited rather than saturated. The default operating point improves from `0.567 -> 0.579` presence accuracy, while precision and safe specificity also move up (`0.5788 -> 0.5961`, `0.642 -> 0.668`) without sacrificing vulnerable recall.
- Scaling again to the full balanced train pool (`20,036` examples) keeps that curve moving in the same direction: the default detector reaches `presence_accuracy = 0.609`, `vulnerable_recall = 0.534`, `safe_specificity = 0.684`, and `precision = 0.6282`.
- The `12k` threshold sweep also improves the detector's best operating points. At `threshold = 0.6`, it reaches `presence_accuracy = 0.601` with `safe_specificity = 0.872`; at `threshold = 0.2`, it reaches `f1 = 0.6718`.
- The full-balanced detector strengthens that conclusion further. On `eval1000`, its threshold sweep reaches `presence_accuracy = 0.630` at `threshold = 0.4`, and its best `f1 = 0.6869` appears at `threshold = 0.3` with `vulnerable_recall = 0.926`.
- That same full-balanced checkpoint also generalizes cleanly to the larger `holdout2000` slice. At the default `0.5` threshold, it reaches `presence_accuracy = 0.6135`, `vulnerable_recall = 0.530`, `safe_specificity = 0.697`, and `precision = 0.6363`, while its best held-out `f1 = 0.6741` appears at `threshold = 0.3`.
- The hybrid detector+auditor system is the first concrete dual-path result in the repo. It preserves the classifier's binary detection strength exactly, while converting outputs into stable structured records with `format_pass_rate = 1.0` and `invalid_output_rate = 0.0`.
- A new `CodeXGLUE detector + support scorer` line clarifies the boundary of the second-stage redesign. Unlike the `PrimeVul` scorer, this scorer does not beat the detector-only branch end-to-end. Its best balanced grid point reaches `presence_accuracy = 0.6055`, `vulnerable_recall = 0.4800`, `safe_specificity = 0.7310`, `precision = 0.6409`, and `f1 = 0.5489`, while the detector-only holdout still reaches `presence_accuracy = 0.6135` and best held-out `f1 = 0.6741`.
- The scorer failure breakdown points back to the detector as the main CodeXGLUE bottleneck. At the best balanced scorer point, `470` vulnerable samples are missed before the scorer is involved, while only `50` vulnerable detector-positive samples are rejected by the scorer.
- That hybrid still inherits the classifier's binary tradeoff (`safe_specificity = 0.642`), and many positive detections lack strong evidence spans. So it is better understood as a practical systems pattern than as a new model-level breakthrough.
- Threshold sweeps strengthen this systems conclusion. The classifier is not really a single point model here; it exposes distinct operating regimes:
  - `0.2`: recall-heavy detector (`vulnerable_recall = 0.956`, `safe_specificity = 0.098`)
  - `0.5`: balanced detector (`vulnerable_recall = 0.488`, `safe_specificity = 0.642`)
  - `0.8`: conservative detector (`vulnerable_recall = 0.188`, `safe_specificity = 0.974`)
- Rebuilding the hybrid at those thresholds preserves the same tradeoff while keeping `format_pass_rate = 1.0`. So the detector+a auditor path is now more than a one-off result: it is an operating-point family that can be tuned for triage, balanced review, or conservative auditing.
- The current working hypothesis is therefore stronger than before: for small-to-mid code models in this repo, the core bottleneck is not just benchmark realism or data size, but the interaction between generative structured SFT and the decision boundary for vulnerable vs. safe code.

*Hybrid `high_confidence_error_rate` is reported as `0.0` because the current stitched records leave confidence unset. That should be read as "not measured" rather than "perfectly calibrated."

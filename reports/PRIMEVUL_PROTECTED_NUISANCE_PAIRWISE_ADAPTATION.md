# PrimeVul Protected Nuisance Adaptation (1,500-Pair Scale-Up)

This experiment scales `docs/LEARNED_JOINT_MODEL_PLAN.md` item 12 ("a protected
objective that retains synthetic side-order supervision while emphasizing
padding invariance") from the 375-pair targeted nuisance pilot
(`reports/PRIMEVUL_NUISANCE_PAIRWISE_ADAPTATION_PILOT.md`) to 1,500 pairs, and
combines the synthetic side-order consistency loss with the nuisance-padding
consistency loss in a single objective rather than the pilot's
mutually-exclusive choice between the two.

Both variants are evaluated at 512 tokens, from the same synthetic-supervised
joint checkpoint (`cls_secure_code_primevul_joint_pairwise_qwen15b_lora_v1`,
`0.8283` BA at 1024 tokens / `0.8174` at 512). Counterfactual rows use
code-only identifier normalization and recompute each checkpoint's own base
predictions, identically to the 375-pair pilot.

## Main Task (Joint Pairwise Format)

| baseline | adapted | delta | repaired | introduced | McNemar p |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0.8174 | 0.8380 | +0.0206 | 26 | 9 | 0.00599 |

The joint-format pair-orientation accuracy improvement is real and
statistically significant (`p=0.006`), and exceeds the original 0.8283
synthetic-supervised checkpoint's headline number even though this run
evaluates at half the token budget (512 vs 1024).

## Counterfactual Relation Success (Independent Single-Text Format)

| intervention | baseline | adapted | delta | repaired | introduced | McNemar p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `context_truncated` | 0.8175 | 0.5350 | -0.2825 | 36 | 149 | 1.556e-17 |
| `format_normalized` | 0.8400 | 0.5025 | -0.3375 | 38 | 173 | 8.967e-22 |
| `identifier_normalized` | 0.8100 | 0.5100 | -0.3000 | 47 | 167 | 5.829e-17 |
| `metadata_removed` | 0.8475 | 0.4900 | -0.3575 | 30 | 173 | 1.245e-25 |
| `nonsecurity_padding` | 0.5750 | 0.4800 | -0.0950 | 78 | 116 | 0.00773 |
| `side_order_swapped` | 0.7500 | 0.5125 | -0.2375 | 56 | 151 | 2.887e-11 |

Every intervention collapsed, including `nonsecurity_padding` -- the
intervention this objective was specifically designed to fix. This is the
opposite of the 375-pair pilot, which held steady or improved on 5 of 6
interventions.

## Diagnosis: Independent Single-Text Calibration Collapse

The counterfactual benchmark scores each row as an independent single-text
classification (one candidate's diff text in, one probability out), not the
joint paired-batch comparison format the model is trained and scored under in
the Main Task table above. Recomputing each checkpoint's own base predictions
in this independent format isolates the effect cleanly:

| Checkpoint | Recomputed base accuracy (independent single-text format) |
| --- | ---: |
| Synthetic-supervised baseline (no consistency/nuisance loss) | 0.80 |
| 375-pair nuisance-only pilot (`nuisance_consistency_weight` only) | 0.79 |
| **1,500-pair protected objective (consistency + nuisance combined)** | **0.50 (exact chance)** |

The baseline and the nuisance-only pilot both function normally as
independent single-text classifiers. The protected-objective checkpoint does
not -- it is indistinguishable from random guessing outside the joint
paired-batch format it was trained under. The joint-format accuracy gain
(`+0.0206`) is real, but it appears to come at the cost of essentially all
standalone single-text calibration, not from genuinely more robust per-text
reasoning.

The most likely cause is the `synthetic_consistency_weight` loss: it trains
the model on `reverse_side_choice_text` views with explicit "Side A / Side B"
framing tokens, optimizing relative within-batch probability relationships
across six co-processed texts per pair (real x2, synthetic-reverse x2,
nuisance x2) rather than any single text's standalone probability. At 375
pairs with nuisance-only supervision this was not yet a problem; combined
with the side-order consistency loss and scaled to 1,500 pairs, it appears to
have pushed the model toward solving the training objective via relative,
context-dependent shortcuts that do not transfer to single-text evaluation.

## Claim Boundary

This is not a successful scale-up of the targeted nuisance pilot. It does not
establish that combining the two consistency losses improves robustness, and
it does not replace the pair-coupled decoding result. It is evidence of a
specific failure mode: combining synthetic side-order consistency with
nuisance-padding consistency at this scale and these weights destroys
independent single-text calibration even while improving joint-format
accuracy. The `nonsecurity_padding` collapse means this run does not even
achieve the pilot's original goal.

This finding does not generalize past the configuration tested here
(`configs/research_primevul_joint_pairwise_protected_nuisance_qwen15b_v1.json`):
one seed, one checkpoint lineage, one set of loss weights. It is not evidence
that combined objectives are unworkable in general, only that this specific
combination at this scale and these weights is not.

## Next Step

Before attempting another combined-objective run, isolate which loss is
responsible: repeat at 1,500 pairs with `synthetic_consistency_weight` alone
(no nuisance term) and check whether the single-text collapse still occurs.
If it does, the side-order consistency loss itself is the cause and any
future protected objective needs an explicit standalone-calibration term
(e.g. a single-text classification loss on the unmodified real candidate
text, supervised independently of the paired-batch relative losses) before
it can be scaled further.

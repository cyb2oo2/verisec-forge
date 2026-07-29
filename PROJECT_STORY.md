# VeriSec Forge Project Story

> **CORRECTED — WITHDRAWN RESULTS.**
> This document previously presented PrimeVul detector results as evidence of learned
> secure-patch reasoning. That interpretation was withdrawn after adversarial
> structural-control analysis. Under the closed-world pair constraint the fine-tuned
> detector reaches balanced accuracy `0.8596`; a **semantics-free character-level diff
> structural control** reaches `0.8588` on the same evaluation population. The difference
> is `+0.0008`, with a pair-group clustered 95% CI spanning zero (`[-0.0202, +0.0222]`)
> and a non-significant group-level sign test (19 vs 18, `p=1.0`).
> **This experiment does not establish semantic secure-patch reasoning beyond diff structure.**
> Current status: [Result Status Ledger](docs/RESULT_STATUS_LEDGER.md).


VeriSec Forge is a shortcut-aware secure patch reasoning project. Its central observation is that vulnerability-detection scores can look impressive on ordinary splits while failing to distinguish the vulnerable and fixed sides of the same patch.

The project should be read as a research system, not as a product demo or a single leaderboard number.

![PrimeVul progressive controls](reports/assets/primevul_progressive_controls.svg)

## One-Sentence Pitch

I built a paired-diff evaluation and audit stack that exposes shortcut-prone secure-code benchmarks, improves side decisions with pair-coupled decoding, and measures how evidence quality fails when the model chooses the wrong side of a patch.

## Research Arc

### 1. Standard Secure-Code Splits Can Mislead

The uncomfortable starting point is that a same-source PrimeVul detector reaches `0.9524` accuracy, but paired vulnerable/fixed evaluation exposes that result as artifact-sensitive. Metadata-only, candidate-only, and counterpart-only controls stay near chance, which makes the paired setup the right unit of evaluation.

Primary evidence:

- [PrimeVul Progressive Controls](reports/PRIMEVUL_PROGRESSIVE_CONTROLS.md)
- [PrimeVul Main Results](reports/PRIMEVUL_MAIN_RESULTS.md)
- [Final Submission Statistics](reports/FINAL_SUBMISSION_STATISTICS.md)

### 2. Paired Diffs Are The Stronger Task Formulation

The paired-diff formulation was originally presented as the project's strongest system result. Adversarial structural controls showed it is not a semantic result.

Current evidence:

- Under the closed-world pair constraint the detector reaches balanced accuracy `0.8596`.
- A semantics-free control reading only the net added-minus-removed **character** count reaches `0.8588` on the same evaluation population.
- The difference is `+0.0008`, pair-group clustered 95% CI `[-0.0202, +0.0222]`, group-level sign test 19 vs 18 (`p=1.0`).
- **No semantic advantage beyond diff structure was established.**

Historical, withdrawn: this section previously reported a diff-only three-seed mean of `0.8287`, a pair-coupled mean of `0.8572`, and a strict delta of `+0.0348` with bootstrap 95% CI `[0.0329, 0.0368]`. That interval resampled five heavily overlapping splits of one frozen prediction set, and the pair-coupled comparison gave the decoder closed-world pair knowledge the baseline did not receive. **Those claims are withdrawn.**

Primary evidence:

- [Pair-Coupled Router](reports/PRIMEVUL_PAIR_COUPLED_ROUTER.md)
- [Pair-Coupled Multi-Split Balanced](reports/PRIMEVUL_PAIR_COUPLED_MULTISPLIT_BALANCED.md)
- [Pair-Coupled Significance](reports/PRIMEVUL_PAIR_COUPLED_SIGNIFICANCE.md)

### 3. Robustness Is Bounded, Not Hand-Waved

The project includes CVE-disjoint, project-disjoint, time-disjoint, DeltaSecommits, and PatchEval checks. These support the main claim while preventing overreach: source-aware expert routing helps, but the learned router is a closed-world source selector, not open-set expert discovery.

VeriPatch-RR v0.1 strengthens the measurement layer before further model
scaling. It separates a within-source representative,
source-macro-balanced primary suite from balanced stress, stores
tokenizer-neutral intervention contracts, and recomputes evidence visibility
with each model's exact fast-tokenizer offsets and truncation policy. Context
pressure is reported as abstention/confidence behavior rather than being
mislabeled as a clean invariance test.

The first frozen Qwen 1.5B mechanism audit then separates three hypotheses.
Moving from `512` to `1024` tokens leaves side-swap equivariance near chance
(`0.4967 -> 0.4850`), so truncation is not the main explanation. Neutral
post-diff padding remains strongly directional at `1024` (`0.4267` relation
accuracy), while adding a terminal task-completion phrase raises relation
consistency to
`0.9050`. Delta separator expansion restores ordinary accuracy
(`0.4700 -> 0.7500`) but not relational robustness. The bounded conclusion is
that representation mismatch and relational inconsistency are distinct
failure modes for this checkpoint.

A first cross-architecture control makes the mechanism claim more precise.
CodeBERT, trained on the same 6,000 bidirectional side-choice rows, reaches
`0.5300` exact-training-contract side-swap equivariance (Qwen `0.4600`) and
`0.9417`
post-diff relation accuracy, compared with Qwen's `0.5650`. This suggests that
relational inconsistency is not Qwen-specific, while the severe terminal
representation dependence is associated with the decoder-style terminal-token
readout in the current comparison. Different pretraining and initialization
still prevent a strict causal architecture claim. The paired endpoint gap is
`+0.3767`, with bootstrap 95% CI `[0.3317, 0.4200]`, and remains positive in
jointly clean, both-canonical-correct, and confidence-matched subsets.
The marginal-conditioned analysis further separates the models: Qwen is close
to independent side decisions, while CodeBERT has a modest positive
equivariance residual but still low both-directions-correct performance.

The next experiment makes the readout hypothesis causal within one Qwen
backbone. With initialization, data order, LoRA targets, loss, seed, and steps
fixed, mean pooling raises post-diff consistency from `0.5533` to `0.8983`,
and changed-hunk pooling reaches `0.9983`. Changed-hunk swap equivariance
remains `0.5017` against a `0.5002` marginal-conditioned baseline, so removing
terminal endpoint sensitivity does not repair side-order reasoning.
First-token pooling collapses because causal decoder token zero cannot observe
the subsequent diff. None of the readouts satisfies the preregistered
canonical-delta tolerance, which keeps this as mechanism evidence rather than
a promoted performance claim.

The independent confirmation preserves that boundary. It excludes all PR #8
discovery pair IDs and suffix templates, then retrains terminal, mean, and
changed-hunk readouts with seeds `7` and `123`. On 180 new pairs, mean and
changed-hunk improve visible-suffix consistency over terminal by `+0.3095`
and `+0.4903`; pair-bootstrap 95% CIs are `[+0.2348, +0.3799]` and
`[+0.4448, +0.5357]`, and both seed-wise effects are positive. However,
canonical non-inferiority is not established: the pooled deltas are `-0.0139`
and `-0.0250`, with confidence bounds extending below the preregistered
`-0.02` margin. This upgrades the readout finding from discovery to a
replicated mechanism result, but it deliberately does not promote either
candidate as an accuracy-preserving classifier. Side-order consistency
remains unresolved.

The frozen-backbone control further purifies the mechanism claim. It freezes
one terminal-trained Qwen+LoRA representation, caches terminal, mean, and
changed-hunk vectors from identical hidden states, and trains matched linear
heads with identical initialization and optimization. Mean pooling's pooled
suffix delta shrinks to `+0.0260` with 95% CI
`[-0.0281, +0.0823]`. Changed-hunk pooling retains `+0.1970` with 95% CI
`[+0.1418, +0.2554]` and positive source-wise effects. The evidence therefore
supports a training-mediated mean effect and a direct structural
changed-hunk effect. The confidence-matched diagnostic has below-10%
coverage, so it is not used as primary evidence. Here, seeds `7` and `123`
are linear-head seeds only; the frozen Qwen+LoRA backbone is the single
terminal-seed7 representation.

Primary evidence:

- [CVE-Disjoint Eval](reports/PRIMEVUL_CVE_DISJOINT_EVAL.md)
- [Project-Disjoint Stress Eval](reports/PRIMEVUL_DISJOINT_STRESS_EVAL.md)
- [Time-Disjoint Comparison](reports/PRIMEVUL_TIME_DISJOINT_COMPARISON.md)
- [DeltaSecommits Expert Eval](reports/DELTASECCOMMITS_DELTA_ONLY_PAIR_DIFF_EVAL.md)
- [PatchEval Multi-Seed Adapter](reports/PATCHEVAL_ADAPTER_MULTISEED.md)
- [Learned Router Claim Boundary](reports/LEARNED_ROUTER_CLAIM_BOUNDARY.md)
- [VeriPatch-RR v0.1](reports/RELATIONAL_BENCHMARK_V2.md)
- [Qwen Relational Mechanism Audit](reports/QWEN_RELATIONAL_MECHANISM_AUDIT.md)
- [Cross-Model Relational Audit](reports/CROSS_MODEL_RELATIONAL_AUDIT.md)
- [Same-Backbone Readout Ablation](reports/READOUT_ABLATION.md)
- [Independent Readout Confirmation](reports/READOUT_CONFIRMATORY.md)
- [Frozen-Backbone Readout Control](reports/FROZEN_BACKBONE_READOUT_CONTROL.md)

### 4. Evidence Is Coupled To The Side Decision

The evidence experiment is **withdrawn as a localization result**. The reported contrast between side-correct and side-wrong localization was circular: the target was computed from the same side decision it was supposed to validate, so flipping the predicted side flips the target deterministically. The small human-confirmation exercise was anchored to windows the pipeline had already proposed (10/10 subset, 0 outside) and therefore cannot measure missed evidence.

Historical, withdrawn: side-correct top-1 `0.7610` versus side-wrong top-1 `0.0632`. These must not be described as localization accuracy or as human-validated evidence quality.

Primary evidence:

- [Pair Evidence Localization](reports/PRIMEVUL_PAIR_EVIDENCE_LOCALIZATION.md)
- [Predicted-Side Hunk Scorer](reports/PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md)
- [Side-Inversion Gate Summary](reports/PRIMEVUL_SIDE_INVERSION_GATE_SUMMARY.md)
- [AI Adjudication Summary](reports/PRIMEVUL_AI_ADJUDICATION_SUMMARY.md)

## What To Emphasize In A PhD Application

The strongest framing is:

> I found a benchmark validity problem in secure-code reasoning, built paired controls to expose it, improved the task with pair-coupled decoding, and used evidence-coupled audit to identify the next modeling bottleneck.

## What this project actually contributes

The project demonstrated that apparently strong vulnerability-detection performance can
collapse or be reproduced by structural shortcuts under stricter paired evaluation.
Adversarial controls showed that character-level diff structure nearly matched the
fine-tuned detector, preventing an unsupported semantic-learning claim.

Concretely:

- A same-source detector scoring `0.9524` falls to `0.4961` under paired evaluation.
- A semantics-free control reading only net added-minus-removed **characters** reaches
  `0.8627` unconstrained — above the fine-tuned detector's `0.8136` — and `0.8588` under
  the pair constraint against the detector's `0.8596`.
- The detector is `0.2584` accurate on rows where that control errs, i.e. below chance:
  it follows the structural shortcut into its errors rather than correcting them.
- Two circular evaluations were identified and withdrawn: an evidence metric whose target
  was derived from the decision it was meant to validate, and a human-confirmation step
  anchored to the pipeline's own proposals.

The contribution is the identification and measurement of shortcut-driven performance,
not a successful semantic vulnerability detector.


This shows research taste: the project does not merely add another model or prompt. It changes the evaluation unit, introduces controls, runs stress tests, and keeps the claim bounded.

## What Not To Overclaim

- Do not present the same-source `0.9524` score as the main achievement.
- Do not claim human-gold evidence spans; the evidence line is still pseudo-label/pilot-audit driven.
- Do not claim open-set source routing.
- Do not present the patch-review UI as a production scanner.
- Do not resurrect old SFT/DPO/verifier branches in the application narrative.

## Next Research Step

The immediate Paper 1 continuation is minimal cross-model replication and
paper/release packaging, without expanding the benchmark or adding more
Qwen-only audits. Side-order relational learning is a separate Paper 2 line:
an antisymmetric pair model should jointly improve swap residual and
both-directions-correct without sacrificing canonical or endpoint behavior.

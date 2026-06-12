# VeriSec Forge Project Story

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

The strongest system result is not standalone vulnerability classification. It is paired patch reasoning: the model sees vulnerable/fixed code as a coupled diff decision, and the decoder enforces coherent pair-level choices when the probability gap is strong enough.

Key evidence:

- Diff-only paired training reaches three-seed mean balanced accuracy `0.8287`.
- Pair-coupled decoding reaches five-split mean balanced accuracy `0.8572`.
- The strict pair-minus-bucket balanced-accuracy delta is `+0.0348`, with bootstrap 95% CI `[0.0329, 0.0368]`.

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
accuracy), while restoring a natural ending raises relation accuracy to
`0.9050`. Delta separator expansion restores ordinary accuracy
(`0.4700 -> 0.7500`) but not relational robustness. The bounded conclusion is
that representation mismatch and relational inconsistency are distinct
failure modes for this checkpoint.

Primary evidence:

- [CVE-Disjoint Eval](reports/PRIMEVUL_CVE_DISJOINT_EVAL.md)
- [Project-Disjoint Stress Eval](reports/PRIMEVUL_DISJOINT_STRESS_EVAL.md)
- [Time-Disjoint Comparison](reports/PRIMEVUL_TIME_DISJOINT_COMPARISON.md)
- [DeltaSecommits Expert Eval](reports/DELTASECCOMMITS_DELTA_ONLY_PAIR_DIFF_EVAL.md)
- [PatchEval Multi-Seed Adapter](reports/PATCHEVAL_ADAPTER_MULTISEED.md)
- [Learned Router Claim Boundary](reports/LEARNED_ROUTER_CLAIM_BOUNDARY.md)
- [VeriPatch-RR v0.1](reports/RELATIONAL_BENCHMARK_V2.md)
- [Qwen Relational Mechanism Audit](reports/QWEN_RELATIONAL_MECHANISM_AUDIT.md)

### 4. Evidence Is Coupled To The Side Decision

Evidence localization is not presented as a solved explanation task. The important result is diagnostic: when pair-coupled side decisions are correct, top-1 evidence localization is much stronger; when the side decision is wrong, localization collapses.

Key evidence:

- Predicted-side top-1 localization: `0.6555`.
- Side-correct top-1 localization: `0.7610`.
- Side-wrong top-1 localization: `0.0632`.

Primary evidence:

- [Pair Evidence Localization](reports/PRIMEVUL_PAIR_EVIDENCE_LOCALIZATION.md)
- [Predicted-Side Hunk Scorer](reports/PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md)
- [Side-Inversion Gate Summary](reports/PRIMEVUL_SIDE_INVERSION_GATE_SUMMARY.md)
- [AI Adjudication Summary](reports/PRIMEVUL_AI_ADJUDICATION_SUMMARY.md)

## What To Emphasize In A PhD Application

The strongest framing is:

> I found a benchmark validity problem in secure-code reasoning, built paired controls to expose it, improved the task with pair-coupled decoding, and used evidence-coupled audit to identify the next modeling bottleneck.

This shows research taste: the project does not merely add another model or prompt. It changes the evaluation unit, introduces controls, runs stress tests, and keeps the claim bounded.

## What Not To Overclaim

- Do not present the same-source `0.9524` score as the main achievement.
- Do not claim human-gold evidence spans; the evidence line is still pseudo-label/pilot-audit driven.
- Do not claim open-set source routing.
- Do not present the patch-review UI as a production scanner.
- Do not resurrect old SFT/DPO/verifier branches in the application narrative.

## Next Research Step

The natural PhD continuation is a contrastive patch model that jointly learns side choice, evidence ranking, and confidence under independently adjudicated evidence spans. The current repository sets up that question with paired controls, stress-tested routing, and a measurable decision-to-evidence failure mode.

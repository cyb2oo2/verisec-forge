# Pointwise Accuracy Is Not Relational Consistency: Auditing Secure Patch Models Under Presentation-Structure Transformations

*4-page cut of `paper/workshop_draft_v1.md` (Path C1: tables in body, figures
moved out). No new experiments or `[RESULT: ...]` anchors. This is a length
target draft, not a venue-template camera-ready.*

## Abstract

Secure-code models are usually evaluated pointwise, but patch review is
relational: a model should identify which side of a vulnerable/fixed pair is
riskier — a candidate-identity judgment, not a directional “does this patch
fix or introduce” judgment. Pointwise accuracy can hide relation-violating
behavior induced by patch presentation structure. Swapping prose side labels
leaves decisions nearly inert, while flipping diff-hunk polarity with gold held
fixed collapses accuracy toward independence. This ordering replicates across a
Qwen decoder and a competency-matched CodeBERT encoder, though the two differ
in functional form — a behavioral phenomenon, not a proven shared mechanism.
Raw CrossVul accuracy is inflated by a stronger version of the same shortcut. A
hard antisymmetric readout is a transferable structural consistency constraint;
a learned fine-tuning objective over it is not validated as transferable
repair. This is a measurement study, not a deployed scanner; evaluation should
report relational consistency alongside pointwise accuracy.

## 1. Introduction, Task, and Instrument

Security patch review asks which side of a vulnerable/fixed pair is riskier and
whether that answer would hold under side swap. Most secure-code evaluation
asks only whether a single snippet is vulnerable
[RELATED: primevul; diversevul; codexglue], measuring detection accuracy but not
the relation between the two sides of a patch. We differ from prior vulnerability
benchmarks by treating patch review as a *relational* task, and from generic
behavioral or counterfactual frameworks
[RELATED: checklist; counterfactual-augmentation] by attaching expected
relations to specific presentation-structure transforms (side swaps, polarity
flips). A model can look competent pointwise while behaving like two nearly
independent classifiers after a side swap.

We study a *candidate-identity* judgment on a pair `x = (A, B)` with gold
`y ∈ {A, B}` naming the riskier side — not a *directional-patch* judgment of
whether a given patch fixes or introduces a vulnerability. Concretely: a
buffer-overflow-vulnerable function (Side A) and its patch (Side B); the
question is which state is riskier, independent of forward vs reverse diff
rendering. Under candidate-identity, diff-hunk polarity is a *nuisance*
variable (Side A/B assignment carries no gold information
[RESULT: polarity-gold-confound]); under directional-patch framing it would be
semantic content. A side-order consistent answer should flip under exact side
swap; we score that against a marginal-conditioned independence baseline.

**VeriPatch-RR** materializes paired PrimeVul / DeltaSecommits / PatchEval
examples per model tokenizer
[RELATED: primevul; deltasecommits; patcheval; qwen25-coder; codebert]. A
same-source PrimeVul detector reaches `0.9524` accuracy while metadata-,
candidate-, and counterpart-only controls stay near chance (`0.5022` / `0.5078`
/ `0.5156` BA) [RESULT: primevul-progressive-controls], so the paired task
carries real relational signal rather than only dataset artifacts. Arc:
**mechanism → polarity → confound → antisymmetric repair**.

## 2. Label-vs-Polarity Findings

A side swap moves prose labels and diff-hunk polarity together. Holding all
else fixed, label-only and polarity-only interventions separate the driver of
side-order failure.

**Table 2. Label-vs-polarity mechanism decomposition (600 base pairs).**
phi is association of a variant’s predictions with canonical (high positive =
inert; near zero = disrupted). Crude-shortcut agreement is per-row agreement
with a net-polarity line-count heuristic on PrimeVul.

| Metric | Qwen | CodeBERT |
| --- | ---: | ---: |
| canonical accuracy | 0.660 | 0.677 |
| label_only_swap phi (vs canonical) | +0.914 | +0.988 |
| polarity_only_swap phi (vs canonical) | −0.094 | −0.193 |
| polarity_only accuracy (gold fixed) | 0.345 | 0.352 |
| crude net-polarity shortcut agreement (PrimeVul) | ~0.57 | ~0.96 |

Sources: [RESULT: qwen-label-only-swap], [RESULT: qwen-polarity-only-swap],
[RESULT: codebert-label-polarity-replication]. Labels are nearly inert;
polarity flips collapse accuracy with gold fixed. This is not generic prompt
sensitivity: both interventions would disrupt under that story, but only
polarity does — evidence for presentation structure, not arbitrary wording.
The ordering replicates on competency-matched CodeBERT. **The functional form
differs** (CodeBERT tracks the crude shortcut far more closely than Qwen), so
this is a cross-architecture *behavioral* ordering, not a shared internal
mechanism. (Figure 5 in the full draft visualizes the same contrast.)

## 3. Cross-Source Confound

CrossVul [RELATED: crossvul] carries a *stronger* polarity/gold presentation
shortcut than PrimeVul [RESULT: crossvul-polarity-gold-confound]:

| Metric | PrimeVul | CrossVul |
| --- | ---: | ---: |
| Crude net-polarity shortcut canonical accuracy | 0.706 | 0.855 |
| Qwen row agreement with shortcut | ~0.57 | ~0.92 |
| CodeBERT row agreement with shortcut | ~0.96 | ~0.93 |

*(Same evidence as §2 / full-draft Table 3 — not a new result.)* CrossVul’s
higher raw canonical accuracy is therefore not standalone evidence of stronger
secure-code reasoning; both architectures lean harder on a stronger measured
shortcut. That Qwen does *not* reduce to the shortcut on PrimeVul (~0.57)
further argues against reading either source’s raw accuracy as a reasoning
signal.

## 4. Repair Decomposition

Having isolated a presentation-structure failure rather than a prompt-wording
artifact, we ask whether side-order consistency can be enforced structurally or
must be learned.

**Table 4. Repair decomposition (canonical accuracy).** “Independent” is
per-rendering readout; “antisymmetric inference” is the projection-null
readout with side-swap invariance exact by construction. Fine-tuning delta is
repaired-minus-baseline under antisymmetric inference.

| Condition | Value |
| --- | ---: |
| baseline, independent inference | 0.660 |
| repaired, independent inference | 0.662 |
| baseline, antisymmetric inference (projection null) | 0.707 |
| repaired, antisymmetric inference | 0.733 |
| FT delta over null (PrimeVul, in-distribution) | +0.027 (McNemar p=0.002) |
| FT delta over null (CrossVul, external) | +0.009 (p=0.508, n.s.) |
| FT delta over null (5 nuisance families) | 0/5 Bonferroni p<0.01; 2/5 sign-reversed |

Sources: [RESULT: antisymmetric-repair]. A hard antisymmetric readout
`s(A,B)=−s(B,A)` makes equivariance and polarity-invariance structural; it
holds on held-out polarity audits, CrossVul, and five nuisance-transform
families while preserving canonical accuracy. A fine-tuning objective over
that readout is significant in-distribution but does **not** transfer
(CrossVul n.s.; 0/5 Bonferroni; 2/5 sign-reversed). We retain the readout as a
structural consistency constraint and leave learned repair unresolved.
(Figure 7 in the full draft plots these conditions.)

## 5. Limitations, Responsible Use, and Artifacts

This is a measurement and mechanism study, not a deployed vulnerability
scanner, and it does not replace human security review; false reassurance from
an unvalidated system is a real risk this study does not resolve. Findings are
scoped to candidate-identity, not directional patch judgment. Evidence is
behavioral (controlled input interventions), not an internal-mechanistic proof;
two architecture families are broader than one model but not a universality
claim, and the Qwen/CodeBERT functional-form divergence (§2) further bounds
shared-mechanism readings. Evidence localization and abstention remain
diagnostics only [RELATED: eraser; attention-not-explanation].

Every number above is tied to a `[RESULT: ...]` anchor via
`paper/result_anchor_map.md` to retained `reports/` JSON; SHA256 manifests sit
under `reproducibility/`. Mechanism/confound/repair tables recompute from
committed predictions without re-running model inference once release
artifacts are present. **CI smoke** checks a 30-pair external-adapter artifact,
anchor integrity, and
`reproducibility/veripatch_external_smoke_manifest.json` `--check-only`; it
does **not** train models, run GPU inference, or treat smoke pairs as a quality
benchmark. Full runtime materialization and large prediction dumps need
**release bundles** — a green CI run does not imply full table reproduction
from a public clone alone.

## Supplement Note

Moved out of this 4-page body (see `paper/workshop_draft_v1.md` /
`paper/draft_v0.md`): Figures 1, 5, 6, 7; full related work; full progressive
controls; full four-row CrossVul Table 3; nuisance-family Bonferroni detail;
readout/endpoint mechanism thread; full appendices.

## Claim Boundaries

This draft does not claim: that secure patch reasoning has been solved;
that this is a deployed vulnerability scanner; a universal failure claim
covering all models; proof of an internal mechanism; a learned repair
claimed as validated or transferable; that this is a production-ready
security tool; or that the system replaces human review.

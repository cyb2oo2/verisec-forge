# Workshop Short-Paper Outline

This is a compression and adaptation **plan**, not a submission draft. It
defines how `paper/draft_v0.md` should be cut down into a SaTML-style
short/workshop paper. It does not rewrite the full paper, does not run
experiments, does not train or tune models, does not change the thesis,
does not add new results, and does not add new `[RESULT: ...]` anchors. No
final PDF is generated here and nothing is submitted from this document.

It builds on `docs/WORKSHOP_PREPRINT_TARGETING_PLAN.md` (positioning and
compression strategy) and `docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md` (the
live venue search that selected the target below) rather than repeating
their reasoning.

## 1. Target and Status

- **Target:** SaTML 2027 (IEEE Conference on Secure and Trustworthy Machine
  Learning), Reykjavik, Iceland, early May 2027.
- **Current official deadline:** September 29, 2026, 11:59 PM AoE, per
  `docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md`'s "SaTML 2027" entry, sourced
  from `https://satml.org/`.
- **Full submission requirements are not yet published and must be
  re-checked before finalizing anything.** As of the shortlist's research
  date, SaTML 2027's page limit, anonymity policy, and preprint policy were
  all marked **unverified** — the site states the full CFP "will be
  announced soon." This outline is written to be *target-aware* (it plans
  against the ~8-page body-text budget `docs/WORKSHOP_PREPRINT_TARGETING_PLAN.md`
  Section 6 already scoped, which fits comfortably inside SaTML 2026's
  historical 5-12pp precedent) without being *overfit* to details that are
  not yet confirmed for the 2027 edition specifically. Every place below
  that depends on an unconfirmed detail says so explicitly rather than
  assuming the 2026 precedent carries forward unchanged.
- **This is an outline, not a submission draft.** No section of
  `paper/draft_v0.md` is edited by this document. The actual compression
  pass is future work (Section 10).

## 2. One-Sentence Thesis

> Pointwise secure-code accuracy can hide relation-violating behavior
> induced by patch presentation structure.

This is the paper's own central finding, stated in `paper/draft_v0.md`'s
Abstract (line 14) verbatim — not a new formulation for the workshop
version. It preserves the existing boundary exactly: it claims a
measurement result (accuracy can hide a specific failure mode), not that
secure patch reasoning is solved, that any model fails universally, or that
an internal mechanism has been proven. No stronger or looser version of
this sentence should replace it in the eventual short paper.

## 3. Intended Contribution List

Four contributions, matching the candidate list this outline was given and
mapping directly onto the paper's existing five contributions
(`paper/draft_v0.md` Section 1) with the readout-mechanism thread (Section
7 of the full draft) deliberately excluded — see Section 6 below for why.

| # | Contribution | Body or appendix/supplement? |
| --- | --- | --- |
| 1 | Candidate-identity task formulation for relation-preserving secure patch evaluation | Body — foundational; needed to justify why diff-hunk polarity is treated as nuisance, and directly preempts the "task may look artificial" reviewer risk (Section 8, item 3) |
| 2 | Controlled label-only vs. polarity-only presentation interventions | Body — this is the headline mechanism result (Figure 5, Table 2); the paper's single strongest claim for a trustworthy-ML audience |
| 3 | Cross-model behavioral replication across Qwen and CodeBERT | Body, compressed — the cross-architecture evidence that keeps the mechanism claim from being a single-model anecdote; full functional-form nuance (crude-shortcut agreement numbers) can compress to one sentence |
| 4 | CrossVul confound and structural-vs-learned repair decomposition | Body, compressed, with the fuller nuisance-transform and Bonferroni accounting moved to supplement — see Sections 5-6 |

This deliberately trims the full draft's five contributions to four by
folding the cross-source confound analysis and the repair decomposition
into one combined contribution (matching the candidate list this outline
was given), and by not carrying the readout-mechanism contribution
(endpoint robustness via readout design, full draft Section 7) into the
workshop version at all — it is a real result but does not support any of
these four contributions and would dilute a short paper's focus. It remains
available in the full paper and is not being discarded, only left out of
this compressed version's scope.

## 4. Proposed Paper Structure

Seven sections targeting roughly 6.75 of the ~8-page body budget
`docs/WORKSHOP_PREPRINT_TARGETING_PLAN.md` Section 6 set, leaving headroom
for introduction/reference polish. Lengths are planning estimates, not
commitments — they will need adjustment once SaTML 2027's actual page limit
is confirmed (Section 1).

### 4.1 Introduction and Motivation

| Field | Plan |
| --- | --- |
| Target length | ~0.75 page |
| Key claim | Patch review is relational; pointwise secure-code evaluation does not test the relation; this motivates VeriPatch-RR |
| Must-include evidence | The one-sentence thesis (Section 2); the three-part half-page framing already specified in `docs/WORKSHOP_PREPRINT_TARGETING_PLAN.md` Section 6 (problem, finding, scope boundary) |
| What to cut from the full draft | The full five-item numbered contribution list compresses to the four items in Section 3; extended positioning prose (full draft's multi-paragraph motivation) compresses to 3-4 sentences |
| Figures/tables | Figure 1 (problem setup) |

### 4.2 Task Formulation and Threat to Pointwise Evaluation

| Field | Plan |
| --- | --- |
| Target length | ~0.75 page |
| Key claim | Candidate-identity ("which side is riskier") is a different question from directional-patch ("does this patch fix or introduce"); diff-hunk polarity is a nuisance variable under the former, not the latter |
| Must-include evidence | The task-boundary argument itself (full draft Section 3, "Task boundary" paragraph); the marginal-conditioned independence baseline concept, since later mechanism numbers are meaningless without it |
| What to cut from the full draft | Formal notation (`T_swap`, full equivariance definition) compresses to prose plus at most one equation; full definitions of both-directions-correct and runtime visibility compress to one sentence each, with the complete definitions moving to supplement |
| Figures/tables | None required in body |

### 4.3 VeriPatch-RR Evaluation Design

| Field | Plan |
| --- | --- |
| Target length | ~0.5-0.75 page |
| Key claim | The instrument measures side-swap equivariance, endpoint robustness, both-directions-correct behavior, and runtime visibility together, so dataset shortcuts and genuine relational failures stay separable |
| Must-include evidence | One sentence on PrimeVul/DeltaSecommits/PatchEval composition; one motivating sentence carrying the benchmark-diagnosis finding (same-source accuracy `0.9524` vs. near-chance progressive controls) rather than the full diagnosis section |
| What to cut from the full draft | The full five-item transformation taxonomy bullet list compresses to one sentence; the runtime-accounting schema (Appendix C material) is not discussed in the body at all |
| Figures/tables | None required in body; Figure 2 is a candidate only if space remains after Sections 4.4-4.6, otherwise supplement (Section 5) |

### 4.4 Mechanism Results: Label vs. Polarity

| Field | Plan |
| --- | --- |
| Target length | ~1.5 pages (the largest section — this is the headline result) |
| Key claim | Swapping the prose side labels leaves the prediction nearly inert; flipping diff-hunk polarity with the gold answer held fixed collapses accuracy and moves the prediction to near-independence — presentation structure, not detection capability, drives the side-order failure |
| Must-include evidence | Table 2's full numeric row set (Qwen phi `+0.914`/`-0.094`, CodeBERT phi `+0.988`/`-0.193`, accuracy collapse `0.660→0.345` and `0.677→0.352`) |
| What to cut from the full draft | The crude-net-polarity-shortcut-agreement comparison (`~0.57` vs. `~0.96`) compresses to one clause; the polarity-vs-full-swap cross-check (`phi=+0.892`) moves to a footnote or supplement |
| Figures/tables | Figure 5 (required), Table 2 (required) |

### 4.5 Cross-Source and Cross-Architecture Checks

| Field | Plan |
| --- | --- |
| Target length | ~1 page |
| Key claim | The label-vs-polarity ordering replicates on a competency-matched CodeBERT encoder, not just Qwen; and CrossVul's higher raw canonical accuracy tracks a *stronger* version of the same presentation confound rather than better reasoning |
| Must-include evidence | The CodeBERT-vs-Qwen canonical-accuracy pairing (already carried by Table 2 from 4.4); the PrimeVul-vs-CrossVul shortcut contrast (`0.706` vs. `0.855` canonical shortcut accuracy; Qwen model-vs-shortcut agreement `~0.57` vs. `~0.92`) — this specific contrast must survive compression in prose even if Table 3 itself moves to supplement, because it is the direct answer to reviewer risk 6 (Section 8) |
| What to cut from the full draft | Full endpoint-gap statistics (`+0.3767` CI etc.) belong to the readout/endpoint thread, which is out of scope for this outline's four contributions (Section 3) — cut or reduce to a single passing clause; the distilgpt2/generative-judge low-canonical stress replication compresses to one sentence acknowledging bounded-but-broader-than-one-model coverage |
| Figures/tables | Figure 6 optional (Section 5); Table 3 recommended for supplement, but its key numeric contrast must still appear in body prose |

### 4.6 Repair Decomposition

| Field | Plan |
| --- | --- |
| Target length | ~1 page |
| Key claim | The antisymmetric structural readout makes side-swap equivariance exact by construction and transfers as a structural constraint; the learned fine-tuning objective layered on top is not validated as a transferable repair |
| Must-include evidence | Table 4's headline rows (independent vs. antisymmetric inference accuracy; McNemar `p=0.002` in-distribution; `p=0.508` on CrossVul; `0/5` nuisance families surviving Bonferroni `p<0.01`) |
| What to cut from the full draft | The full per-family nuisance-transform breakdown and Bonferroni accounting detail move to supplement; keep only the "0/5 families, 2 sign-reversed" headline in body |
| Figures/tables | Figure 7 (required), Table 4 (required) |

### 4.7 Limitations and Responsible Use

| Field | Plan |
| --- | --- |
| Target length | ~1 page |
| Key claim | This is a measurement and mechanism study, not a deployed tool; the evidence is behavioral, bounded in model-family coverage, and the repair result is structural rather than learned |
| Must-include evidence | The full draft's highest-value limitations points, compressed: behavioral-not-mechanistic; bounded model-family claim; structural-not-learned repair; candidate-identity task scope. **Depends on** the responsible-use paragraph `docs/PREPRINT_PREPARATION_PLAN.md` Section 8 recommended but has not yet been written — this section cannot be finalized until that dependency lands (Section 10) |
| What to cut from the full draft | The full draft's eleven-paragraph Limitations section compresses to roughly five to six sentences; bootstrap-protocol-conditional and model-tokenizer-specific runtime-visibility caveats move to a supplement footnote |
| Figures/tables | None |

## 5. Figure/Table Selection

| Item | Disposition | Reasoning |
| --- | --- | --- |
| Figure 1 (problem setup) | **Required in body** | Sets up the thesis visually in the space of the introduction; essential for a reviewer skimming the first page (Section 4.1) |
| Figure 5 (label vs. polarity mechanism) | **Required in body** | The headline mechanism finding; this is the single figure the paper cannot compress away without losing its strongest result (Section 4.4) |
| Figure 6 (CrossVul confound) | **Optional in body** | Strong fit for SaTML's evaluation-rigor-focused audience — arguably more relevant here than at an AI4Code venue — but not the single headline; include only if 4.4 and 4.6 fit their targets with room to spare, otherwise supplement |
| Figure 7 (repair decomposition) | **Required in body** | Second major contribution (structural-vs-learned distinction); matches a trustworthy-ML audience's interest in what does and does not count as a validated mitigation (Section 4.6) |
| Table 2 (Qwen/CodeBERT mechanism comparison) | **Required in body** | Compact, carries the exact numbers Figure 5 illustrates; needed alongside Figure 5, not instead of it |
| Table 3 (CrossVul confound) | **Move to supplement** | The finding compresses to a body sentence (Section 4.5); the full table's four-row breakdown is supplementary detail. **Caveat:** the specific PrimeVul-vs-CrossVul numeric contrast this table carries must still appear in body prose regardless, because it directly answers reviewer risk 6 (Section 8) — moving the table out does not mean moving the finding out |
| Table 4 (repair decomposition) | **Required in body** | Compact, carries contribution 4's numbers directly; pairs with Figure 7 the same way Table 2 pairs with Figure 5 |

Figures 2, 3, and 4 (VeriPatch-RR transformation taxonomy; readout-ablation
mechanism detail) are not candidates for the body at all, consistent with
`docs/WORKSHOP_PREPRINT_TARGETING_PLAN.md` Section 6 and this outline's
Section 3 decision to leave the readout-mechanism thread out of the four
chosen contributions — they move to supplement or are cut, not selected
here.

## 6. What to Compress

Mapping each section of `paper/draft_v0.md` to a disposition and to where
its surviving content lands in the Section 4 structure. This mapping exists
to make the compression concrete, not to narrate the repository's history —
each row states what the *workshop paper* will do, not what happened to
produce the current draft.

| Full-draft section | Disposition | Lands in (Section 4) |
| --- | --- | --- |
| Abstract | Compress heavily | Rewritten to match the one-sentence thesis (Section 2) plus 2-3 supporting sentences |
| 1. Introduction | Compress heavily | 4.1 — five contributions trim to four (Section 3) |
| 2. Related Work and Positioning (2.1-2.5) | Move to supplement / compress heavily | 4.1 — a short paper does not carry five related-work subsections; compress to 2-4 sentences naming the closest related lines (behavioral/counterfactual evaluation, code model benchmarks), full subsection detail moves to supplement |
| 3. Problem Formulation | Compress heavily, keep the core argument | 4.2 — the candidate-identity/directional-patch distinction is kept in full argumentative force since it is load-bearing for reviewer risk 3 (Section 8); formal notation compresses |
| 4. VeriPatch-RR | Compress heavily | 4.3 |
| 5. Benchmark Diagnosis | Move to supplement, one sentence survives in body | 4.3 — the same-source-`0.9524`-vs-near-chance-controls story becomes one motivating sentence; the full progressive-controls table and discussion move to supplement |
| 6.1 Competency-Controlled Architecture Comparison | Compress heavily | 4.5 — headline canonical-accuracy pairing survives; endpoint-gap statistics are cut (out of scope for the four chosen contributions) |
| 6.2 Low-Canonical Stress Replication | Compress heavily to one sentence | 4.5 — supports reviewer risk 2 (limited model families) cheaply without carrying full distilgpt2/generative-judge numbers into the body |
| 6.3 What Drives Side-Order Failure | Keep | 4.4 — this is the headline mechanism section; kept nearly intact, only the secondary crude-shortcut-agreement clause compresses |
| 6.4 CrossVul: Presentation Confound | Compress, key contrast kept in prose | 4.5 |
| 7. Readout Mechanism (7.1-7.4, all subsections) | **Move to supplement or cite forward to the full paper; not reconstructed in the workshop body** | Not in Section 4 at all — this is the readout-endpoint-robustness thread the Section 3 contribution list deliberately excludes; a single forward-pointing citation to the full paper is sufficient if it is mentioned at all |
| 8. Repair | Keep, compress the transfer-detail breakdown | 4.6 |
| 9. Limitations | Keep, heavily compressed | 4.7 |
| 10. Discussion | Compress heavily, fold into 4.1 and 4.7 | Key point (report relational consistency alongside pointwise accuracy) becomes the closing sentence of 4.1 or 4.7; the rest is cut as a standalone section — a short paper's discussion is its introduction's closing claim, not a separate section |
| Appendices A-E | Move to supplement in full | Referenced by a single "reproducibility and full protocol details in supplementary material" pointer, not reproduced |

This compression keeps the workshop paper focused on the four contributions
in Section 3 and avoids two specific failure modes: reading as a benchmark-
engineering paper (by cutting Section 4's instrument-construction detail
down to one paragraph, per `docs/WORKSHOP_PREPRINT_TARGETING_PLAN.md`
Section 6) and reading as a repository changelog (by never describing what
was removed in terms of PR numbers, commit history, or "this used to
include" language — every row above states what the *target* document
contains, not what was subtracted from an artifact).

## 7. Claim-Boundary Checklist

The workshop version must preserve every boundary the full draft already
holds. Written in the same negated form the draft itself already uses, so
nothing below reads as a bare assertion of the claim it warns against.

**Do not claim:**

- that secure patch reasoning has been solved;
- that this is a deployed vulnerability scanner;
- a universal failure claim covering all models;
- proof of an internal mechanism;
- a learned repair claimed as validated or transferable;
- that this is a production-ready security tool;
- that the system replaces human review or a human reviewer.

This list is identical in substance to `docs/WORKSHOP_PREPRINT_TARGETING_PLAN.md`
Section 7's paper-level claim boundary, restated here so the compression
work in Sections 4-6 has an explicit checklist to verify against once the
actual short-paper text is drafted (Section 10). Every cut and every
compression decision above should be checked against this list before the
outline becomes a draft: a compressed sentence can accidentally overclaim
in a way its longer original did not, simply by dropping a qualifying
clause under space pressure. The specific risk points are Sections 4.4-4.6
(mechanism, cross-source, and repair claims are the ones most likely to
tighten into an overclaim when compressed) and the Section 4.7 limitations
compression itself, which exists specifically to prevent that.

## 8. Reviewer-Risk Analysis

Six likely SaTML-style objections. Per the instruction this outline was
given, this section is strict: where the existing draft already has the
evidence to answer an objection, that is stated and cited; where it does
not, that is stated plainly rather than papered over.

| Objection | Answer strategy | Where the draft already supports it | New experiment needed? |
| --- | --- | --- | --- |
| Only behavioral evidence, not internal mechanism | State this as an intentional, disclosed scope boundary, not a hidden weakness — the draft never claims otherwise | `paper/draft_v0.md` §6.3, §9: "behavioral... not a proven shared internal mechanism" | No |
| Limited model families | Name the actual coverage precisely — two competency-matched primary architectures (Qwen decoder, CodeBERT encoder) plus two explicitly-labeled low-canonical stress models (distilgpt2, a small generative judge) — and state the bounded-generality claim directly rather than defensively | §6.2, §9: "broader than one model but is not a universality claim" | No, to defend the claim as currently scoped. A third competency-matched family would strengthen the evidence but is not required to answer this specific objection, since the claim is already bounded to match the evidence that exists |
| Candidate-identity task may look artificial | Point to the task-boundary argument as a deliberate, defended methodological choice, not an oversight; cite the fuller argument for space reasons rather than re-deriving it | §3 "Task boundary" paragraph; Appendix D prompt contract; `docs/TASK_FORMULATION.md` | No |
| Not a deployed security tool | Agree explicitly and reframe as the study's intended scope, not a limitation to apologize for | Abstract; §9 opening | No |
| Repair result is mostly structural | State plainly that the antisymmetric constraint is retained as a real, transferable mitigation, while the learned fine-tuning layer is explicitly reported as unresolved — present this as negative-result discipline the paper already practices, not a gap being defended after the fact | §8, Table 4, with McNemar p-values already reported for all three transfer legs | No |
| Benchmark-source confounds may weaken the benchmark's own framing | This is the sharpest objection on the list: if CrossVul is confounded, why trust PrimeVul is not similarly confounded? The answer already exists in the draft: PrimeVul carries a *weaker* version of the same net-polarity shortcut (`0.706` canonical shortcut accuracy vs. CrossVul's `0.855`), and critically, Qwen's actual behavior does not reduce to that weaker shortcut (row agreement `~0.57`, whereas CodeBERT tracks it closely at `~0.96` on PrimeVul) — the paper already measures a model- and source-dependent confound rather than asserting PrimeVul is confound-free by fiat | §6.4, Table 3; `[RESULT: polarity-gold-confound]`, `[RESULT: crossvul-polarity-gold-confound]` | No — the evidence already exists. **But there is a real compression dependency**: Section 5 recommends moving Table 3 to supplement. If the body's one-sentence summary of Section 4.5 does not explicitly carry the PrimeVul-vs-CrossVul numeric contrast, this defense stops being visible to a reviewer who only reads the body — the evidence existing in the full paper is not the same as the evidence surviving compression. This is the single sharpest interaction between Sections 5-6's compression choices and this section's reviewer-risk defense, and should be checked explicitly when the short-paper text is actually drafted (Section 10) |

## 9. Submission Preparation Blockers

| Item | Classification | Note |
| --- | --- | --- |
| Real author metadata | **Blocker** | `CITATION.cff` still carries a placeholder author (`docs/PREPRINT_PREPARATION_PLAN.md` Section 3); needed for the eventual camera-ready record even though the submission itself will be anonymized |
| Anonymization strategy | **Blocker** | SaTML 2026's precedent was double-blind; the 2027 policy is unconfirmed (Section 1), but preparing an anonymization pass (author/institution references, self-citation in third person, repository-link handling) is the safe default regardless of what the 2027 CFP eventually confirms |
| Official SaTML 2027 submission requirements once published | **Blocker** | Literally cannot finalize a submission without them; `docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md` already flags this as unverified and to be re-checked before the deadline |
| Page limit once published | **Blocker** | Same reasoning; the ~8-page planning target (Section 4) is a safe assumption given it fits SaTML 2026's historical 5-12pp range, but is not a confirmed number for 2027 |
| PDF build path | **Blocker** | Unresolved per `docs/PREPRINT_PREPARATION_PLAN.md` Section 3; no submission can be produced without it regardless of venue |
| Artifact anonymization, if required | **Should-fix** | Not confirmed required by SaTML specifically (Section 1's unverified fields), but double-blind submissions commonly require anonymized repository links; prudent to prepare without waiting for confirmation |
| Responsible-use / AI-use disclosure | **Should-fix** | Not confirmed required by SaTML's unpublished CFP, but increasingly common at ML/security venues, and `docs/PREPRINT_PREPARATION_PLAN.md` Section 8 already recommended a responsible-use paragraph independent of any venue's requirement. Becomes a blocker if SaTML 2027's eventual CFP explicitly requires an AI-use disclosure statement |
| Final abstract/title pass | **Optional** | `docs/PREPRINT_PREPARATION_PLAN.md` Section 9 already found the title sound and the abstract needing only light density polish — low effort, not blocking |

## 10. Recommended Next PR

Options considered, per this outline's brief:

- A. `paper: add preprint metadata and responsible-use statement`
- B. `paper: compress draft into workshop skeleton`
- C. `paper: create PDF build path`
- D. `docs: prepare anonymized artifact plan`
- E. `research: define real-world directional patch review task`

**Recommendation: A — `paper: add preprint metadata and responsible-use
statement`.**

Rationale:

- **A resolves work that is entirely within the author's control right
  now**, independent of SaTML 2027's still-unpublished CFP. Author
  metadata, the responsible-use paragraph, and an AI-use disclosure
  statement do not depend on any external confirmation the way B, C, and D
  partly do.
- **Doing A before B avoids rework.** Section 4.7's compression explicitly
  depends on the responsible-use paragraph existing (Section 4.7's "Must
  include evidence" row states this directly). Compressing the draft (B)
  before that paragraph exists means either compressing without it and
  redoing the limitations section later, or blocking B on A anyway — doing
  A first avoids the ordering problem entirely.
- **Doing A before C avoids rework too.** Building a PDF (C) from a draft
  whose author metadata is still a placeholder means rebuilding once A
  lands, the same reasoning `docs/PREPRINT_PREPARATION_PLAN.md` Section 11
  already used to sequence its own recommendation.
- **D is premature.** Whether SaTML requires artifact anonymization is
  explicitly unconfirmed (Section 9); preparing a detailed anonymized-
  artifact plan before knowing whether one is required risks planning
  against the wrong requirement once the real CFP publishes.
- **E is out of scope.** A new research direction (real-world directional
  patch review) is a different line of work entirely and would reintroduce
  the new-experimental-work this outline and its predecessor plans were
  both explicitly scoped to avoid.
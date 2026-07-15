# Pointwise Accuracy Is Not Relational Consistency: Auditing Secure Patch Models Under Presentation-Structure Transformations

*Draft status: this is a prose short-paper draft for SaTML 2027, not final
typeset copy. Page length has not been validated against a page-limit or
formatting path, since SaTML 2027's own page limit is not yet published
(see "Open Submission Requirements" below) and no PDF build path exists
yet for this project. Do not treat this draft's current length as a
confirmed fit for any page budget. Built from `paper/workshop_draft_skeleton.md`,
`paper/draft_v0.md`, `paper/references.md`, and `paper/result_anchor_map.md`;
every number and citation below is copied from those sources — no new
experiments, results, or `[RESULT: ...]` anchors were introduced to produce
this draft.*

## Abstract (150-180 words)

Secure-code models are usually evaluated pointwise, but patch review is
relational: a model should identify which side of a vulnerable/fixed pair
is riskier — a candidate-identity judgment, not a directional "does this
patch fix or introduce" judgment. Pointwise secure-code accuracy can hide
relation-violating behavior induced by patch presentation structure. Under
a controlled decomposition, swapping the prose side labels leaves a
model's decision nearly inert, while flipping diff-hunk polarity with the
gold answer held fixed collapses accuracy and moves the decision toward
independence. This ordering replicates across a Qwen decoder and a
competency-matched CodeBERT encoder, though the two differ in functional
form — a behavioral phenomenon, not a proven shared mechanism. Raw
canonical accuracy on CrossVul, an external source, is inflated by a
stronger version of the same shortcut. A hard antisymmetric readout is a
transferable structural consistency constraint, while a learned
fine-tuning objective over it is not validated as transferable repair.
This is a measurement study, not a deployed vulnerability scanner, and it
does not replace human security review; we recommend secure-patch
evaluation report relational consistency alongside pointwise accuracy.

## 1. Introduction

Security patch review is comparative: a reviewer asks which side of a
vulnerable/fixed pair carries the risk, and whether that answer would hold
if the two sides were presented in the opposite order. Most secure-code
evaluation reduces this to a pointwise question — is a single snippet
vulnerable? [RELATED: primevul; diversevul; codexglue] — which measures
detection accuracy but not whether a model represents the relation between
the two sides of a patch. A model can look competent on individual
examples while behaving like two nearly independent classifiers once the
sides of a pair are swapped; that is not an ordinary classification error,
it is a failure of a structural property the task requires.

[Figure 1 here]

This paper makes three tightly-scoped contributions: a candidate-identity
task formulation for relation-preserving secure patch evaluation; a
controlled decomposition isolating diff-hunk polarity, not prose side
labels, as the driver of side-order failure, replicated across a Qwen
decoder [RELATED: qwen25-coder] and a competency-matched CodeBERT encoder
[RELATED: codebert]; and a structural-vs-learned decomposition of an
antisymmetric repair. This is a measurement and mechanism study, not a new
vulnerability scanner, and its scope is deliberately narrower than a full
technical report — see `paper/draft_v0.md` for the complete evidence base,
appendices, and reproduction protocol this draft compresses.

## 2. Task Formulation

We consider a paired patch input `x = (A, B)`, two rendered sides of a
vulnerable/fixed pair, with gold label `y ∈ {A, B}` identifying the riskier
side. Our task is a *candidate-identity* judgment — which of two related
code states is riskier — not a *directional-patch* judgment of whether a
given patch fixes or introduces a vulnerability. The distinction governs
how diff-hunk polarity should be treated: under the directional-patch
framing, polarity (which code sits on removed vs. added lines) is semantic
content a model should use; under candidate-identity, Side A and Side B
denote fixed code regardless of how their difference is rendered, so
polarity is a *nuisance variable* a robust model's decision should not
depend on. We treat polarity as nuisance because Side A/Side B assignment
is independent of which side is vulnerable in our benchmark, so rendering
orientation carries no information about gold [RESULT: polarity-gold-confound].
A side-order consistent model's answer should flip under an exact side
swap; measuring whether it does — against a marginal-conditioned
independence baseline rather than a naive chance line — is the evaluation
threat this paper studies.

## 3. VeriPatch-RR Evaluation Design

VeriPatch-RR is a paired vulnerable/fixed patch benchmark built from
PrimeVul [RELATED: primevul], DeltaSecommits [RELATED: deltasecommits], and
PatchEval [RELATED: patcheval], materialized per model tokenizer so
truncation and evidence visibility are part of the experimental record
rather than a post hoc explanation. It separates ordinary accuracy from
side-order equivariance, both-directions-correct behavior, and endpoint
robustness, treating each transformation as a relation test only when its
expected relation is specified before evaluation — an approach closest in
spirit to behavioral and counterfactual evaluation more broadly
[RELATED: checklist; counterfactual-augmentation]. A same-source PrimeVul
detector reaches `0.9524` accuracy, but paired negative controls
(metadata-only `0.5022`, candidate-only `0.5078`, counterpart-only `0.5156`
balanced accuracy) stay near chance [RESULT: primevul-progressive-controls]
— protecting the claim that the paired task carries real relational signal
rather than only dataset artifacts.

## 4. Label-vs-Polarity Findings

[Figure 5 here]

[Table 2 here]

The side-swap transformation moves two factors at once: the prose side
labels and the diff-hunk polarity. Decomposing them on the Qwen classifier,
holding everything else fixed: swapping only the prose labels leaves the
prediction almost unchanged (phi `+0.914` vs. canonical) [RESULT: qwen-label-only-swap];
flipping only the polarity, with the labels and gold held fixed, moves the
prediction to near-independence (phi `-0.094`) and collapses accuracy from
`0.660` to `0.345` even though gold is unchanged [RESULT: qwen-polarity-only-swap].
This decomposition replicates on the competency-matched CodeBERT encoder
(canonical `0.677`): label-only swap is inert (phi `+0.988`), polarity-only
swap is disruptive (phi `-0.193`), collapsing accuracy `0.677` to `0.352`
[RESULT: codebert-label-polarity-replication]. The functional form
differs — CodeBERT tracks a crude net-polarity shortcut on PrimeVul
(`~0.96` agreement) far more closely than Qwen does (`~0.57`) — so the
evidence supports a cross-architecture *behavioral* ordering, not a shared
internal mechanism.

## 5. Cross-Source and Cross-Architecture Checks

We measure the same net-polarity/gold structure on CrossVul
[RELATED: crossvul], an external source, and find it carries a *stronger*
presentation shortcut than PrimeVul: the crude net-polarity heuristic
reaches `0.855` canonical accuracy on CrossVul vs. `0.706` on PrimeVul, and
both Qwen (`~0.92`) and CodeBERT (`~0.93`) align strongly with that
shortcut there [RESULT: crossvul-polarity-gold-confound]. Qwen's row-level
agreement with the crude shortcut on PrimeVul is only `~0.57` — close to
the level expected if Qwen's behavior does not simply reduce to that
shortcut — while CodeBERT's is `~0.96`, the same contrast reported in
Section 4. CrossVul's higher canonical accuracy should therefore not be
read as stronger secure-code reasoning; it coincides with a stronger
measured presentation shortcut both architectures lean on more heavily than
either does on PrimeVul, and the fact that Qwen does not reduce to that
shortcut on PrimeVul is itself evidence against reading either source's
raw accuracy as a standalone reasoning signal.

## 6. Repair Decomposition

[Figure 7 here]

[Table 4 here]

We separate two claims that are easy to conflate. A hard antisymmetric
readout — a pairwise scorer with `s(A, B) = -s(B, A)` by construction —
makes side-swap equivariance exact and polarity-invariance structural
rather than learned. Evaluated on the held-out polarity audit, on
CrossVul, and on five held-out nuisance-transform families, this
structural constraint holds and preserves canonical accuracy
[RESULT: antisymmetric-repair]. The *learned* part is different: a
fine-tuning objective layered over the antisymmetric readout showed a
canonical-accuracy increment that was significant in-distribution (McNemar
`p = 0.002`) but did not survive transfer — not significant on CrossVul
(`p = 0.508`), and clearing no family at a Bonferroni-corrected threshold
across the five nuisance transforms, with two families reversing sign
[RESULT: antisymmetric-repair]. The antisymmetric readout is retained as a
transferable structural consistency constraint; the learned fine-tuning
objective is left unresolved.

## 7. Limitations and Responsible Use

This is a measurement and mechanism study, not a deployed vulnerability
scanner, and it does not replace human security review; a confident wrong
answer is more dangerous in security review than an abstention, so false
reassurance from an unvalidated system is a real risk this study does not
resolve. The task studied is candidate-identity — which of two related
code states is riskier — not a directional judgment of whether a patch
fixes or introduces a vulnerability, and the findings should not be read
past that boundary. Evidence localization and abstention are the
mechanisms a real deployment would need and are evaluated here only as
diagnostics; any deployment-facing use of this evaluation approach
requires additional validation beyond what is reported here. The mechanism
evidence is behavioral — controlled input interventions on model outputs —
not an internal-mechanistic proof; the label-vs-polarity ordering
replicates across two architecture families, which is broader than one
model but is not a universality claim.

## Supplement Note

The following move out of the body into supplementary material:

- Full related-work positioning — the body keeps a short pointer only.
- Full benchmark-diagnosis detail (the progressive-controls table and
  discussion behind Section 3's motivating sentence).
- **The full Table 3 CrossVul confound breakdown moves to supplement, but
  its key numeric contrast — PrimeVul's weaker shortcut (`0.706`) vs.
  CrossVul's stronger one (`0.855`), and Qwen's low row agreement with it
  (`~0.57`) vs. CodeBERT's high agreement (`~0.96`) — stays in body prose
  in Section 5 above**, because it is the direct answer to the reviewer
  objection that benchmark-source confounds could undermine this paper's
  own framing.
- Full nuisance-transform repair detail (the per-family Bonferroni
  accounting behind the "0/5 families, 2 sign-reversed" headline in
  Section 6).
- Full appendices and reproduction/protocol details, referenced by a
  single pointer rather than reproduced.

## Claim Boundaries

This draft does not claim: that secure patch reasoning has been solved;
that this is a deployed vulnerability scanner; a universal failure claim
covering all models; proof of an internal mechanism; a learned repair
claimed as validated or transferable; that this is a production-ready
security tool; or that the system replaces human review or a human
reviewer.

## Open Submission Requirements

SaTML 2027's full submission requirements — page limit, anonymity policy,
preprint/dual-submission policy, and AI-use disclosure formatting — are
not yet published and must be re-checked against
`https://satml.org/call-for-papers/` before final page-limit decisions,
anonymity decisions, preprint timing, and AI-use disclosure formatting are
locked in. This draft plans against SaTML 2026's historical 5-12pp
precedent as the best available estimate, not a confirmed 2027 requirement.

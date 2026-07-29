# Workshop Draft v0 Readiness Audit

> **HISTORICAL DOCUMENT — CONTAINS WITHDRAWN RESULTS.**
> Contains results or interpretations withdrawn after adversarial structural-control
> analysis. Under the closed-world pair constraint the detector reaches `0.8596` balanced
> accuracy and a semantics-free character-level diff control reaches `0.8588` on the same
> population; the difference (`+0.0008`, clustered 95% CI `[-0.0202, +0.0222]`, sign test
> 19 vs 18, `p=1.0`) is not distinguishable from zero.
> **Do not cite as the repository's current scientific conclusion.**
> Current status: [Result Status Ledger](../docs/RESULT_STATUS_LEDGER.md).


A strict, reviewer-like audit of `paper/workshop_draft_v0.md`, not a
self-congratulatory summary. It does not run experiments, train or tune
models, rewrite the draft, build a PDF, anonymize artifacts, submit
anywhere, or add new empirical claims, results, or `[RESULT: ...]` anchors.
Every finding below was checked directly against the current text of
`paper/workshop_draft_v0.md`, cross-referenced with `paper/workshop_short_paper_outline.md`,
`paper/workshop_draft_skeleton.md`, `docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md`,
`docs/AI_USE_DISCLOSURE_DRAFT.md`, `paper/draft_v0.md`,
`paper/result_anchor_map.md`, and `paper/references.md` — not recalled from
memory of writing it.

## 1. Overall Verdict

| Question | Verdict | Why |
| --- | --- | --- |
| Is `paper/workshop_draft_v0.md` a real workshop draft? | **YES** | It is flowing prose with integrated citations and real numbers, not an outline or bullet list — a genuine step beyond `paper/workshop_short_paper_outline.md` and `paper/workshop_draft_skeleton.md`. |
| Is it ready for internal editing? | **READY** | The structure is sound enough to revise directly rather than rewrite from scratch — see Section 8's bounded, concrete edit list. |
| Is it ready for external workshop submission? | **NOT READY** | Two independent reasons. First, content gaps this audit found (Section 3): no related-work positioning sentence despite the Supplement Note claiming one exists, a hard-to-parse CrossVul paragraph without a table to anchor six numbers, and no concrete example of the candidate-identity task. Second, and independent of draft quality: SaTML 2027's own submission requirements are still unpublished, so no formatting, anonymity, or page-limit decision can be finalized regardless of text quality. |
| Is it ready for PDF/typesetting? | **NOT READY** | No PDF build path exists yet (`docs/PREPRINT_PREPARATION_PLAN.md` Section 3, still unresolved), and the text itself should stabilize through a v1 pass (Section 8) before typesetting effort is spent on it — typesetting text that is about to change is wasted work. |

Being strict: this is a genuinely usable draft, not a failed one — the
verdict split is not "bad draft," it is "good enough to be worth revising
carefully rather than good enough to submit as-is." The distinction matters
because the fixes below are edits, not a structural rewrite.

## 2. What Works

| Strength | Assessment |
| --- | --- |
| Thesis clarity | Strong. The one-sentence thesis appears in the Abstract, is never contradicted, and every section traces back to it. A reader who reads only the abstract leaves with the correct central claim. |
| Workshop-focused compression | Mostly strong. The draft is meaningfully shorter than `paper/draft_v0.md` while keeping the four contributions `paper/workshop_short_paper_outline.md` Section 3 selected — the compression executed the plan it was given. |
| Candidate-identity explanation | Correct but not yet accessible — see Section 3 below. The formal distinction (Section 2 of the draft) is accurate and matches `paper/draft_v0.md` §3 exactly, but accuracy and accessibility are different properties, and this section has the former without yet having the latter. |
| Label-vs-polarity result | Strong. This is the best-executed section in the draft: the numbers are complete, the phi/accuracy contrast is stated clearly, and the behavioral-not-mechanistic boundary is explicit in the same paragraph as the result, not deferred to limitations. |
| Qwen/CodeBERT replication | Strong. Folded into the same section as the label-vs-polarity result rather than treated as a separate afterthought, which is the right compression choice — it reads as one finding replicated twice, not two findings. |
| CrossVul confound handling | **Content is correct, presentation is weak** — see Section 3. The right numbers are present and the right conclusion is drawn, but six numbers in prose with no table is a real readability cost this audit did not expect to find until reading the section closely. |
| Repair decomposition | Content is strong (the structural-vs-learned distinction and both p-values are present and correctly framed), but the section opens abruptly — no sentence connects it back to the side-order problem established in Sections 1-4, so it reads as a topic switch rather than the paper's second act. |
| Responsible-use boundary | Strong. Section 7 restates the exact responsible-use language `paper/draft_v0.md` §9 already carries (not a new claim), and covers all the required points: not deployed, does not replace human review, false reassurance risk, candidate-identity scope, evidence-localization/abstention as deployment-readiness gates. |

## 3. Biggest Weaknesses

Ranked by severity. All nine candidate issues this audit was asked to
examine are addressed below; several turned out to be real and specific,
one turned out to be already well-handled, and one is not fixable by
editing at all.

### 3.1 CrossVul confound explanation is hard to parse (High)

**Why it matters:** Section 5 packs six numbers into three sentences of
prose (`0.855`, `0.706`, `~0.92`, `~0.93`, `~0.57`, `~0.96`) with no table
to anchor them. This is not a hypothetical risk — this section carries the
draft's defense against its single sharpest reviewer objection (Section 4,
item 5: "CrossVul confounds weaken the benchmark"), and a defense a
reviewer cannot parse on a first read is a weaker defense regardless of
whether the underlying evidence is sound. The compression choice that
moved Table 3 out of the body (per `paper/workshop_short_paper_outline.md`
Section 5) optimized for page budget at a real cost to this specific
section's legibility.

**Recommended fix:** Return a reduced 2-row version of Table 3 to the body
(crude-shortcut canonical accuracy row; model-vs-shortcut agreement row),
or restructure the prose into an explicit parallel construction ("On
PrimeVul: shortcut accuracy `0.706`, Qwen agreement `~0.57`. On CrossVul:
shortcut accuracy `0.855`, Qwen agreement `~0.92`.") so the contrast is
scannable without a table. See Section 5 of this audit for the full
figure/table recommendation.

**New evidence needed:** No — this is a presentation fix, not an evidence
gap. The numbers are already correct and already cited.

### 3.2 The promised related-work pointer does not exist in the body (High)

**Why it matters:** The draft's own Supplement Note states "Full
related-work positioning — the body keeps a short pointer only." This
audit checked the body text directly for any related-work positioning
sentence (searching for "related work," "prior work," "closest in spirit,"
and similar phrasing) and found **none** — citations to prior benchmarks
(`[RELATED: primevul; diversevul; codexglue]`) and to behavioral evaluation
(`[RELATED: checklist; counterfactual-augmentation]`) are dropped inline
without a synthesizing sentence distinguishing this work from them. The
Supplement Note is currently making a promise the body does not keep. This
also means the draft is not yet doing the minimum positioning work a
workshop reviewer expects — even a compressed paper needs one sentence
saying how it differs from the nearest prior approach, not just a citation
tag.

**Recommended fix:** Add one sentence to the Introduction, immediately
after the first citation clause, stating the positioning directly — e.g.,
that this work differs from prior vulnerability benchmarks and from
generic behavioral-testing frameworks by treating vulnerable/fixed patch
review as a relational task rather than a pointwise label or a generic
robustness check. `paper/draft_v0.md` §2.5 "Positioning" already has this
exact sentence in fuller form and can be compressed directly rather than
written from scratch.

**New evidence needed:** No — the positioning claim already exists in the
full paper and needs compression, not new argument.

### 3.3 Candidate-identity task has no concrete example (High)

**Why it matters:** Section 2's task formulation is accurate but entirely
abstract — formal notation (`x = (A, B)`, `y ∈ {A, B}`) with no worked
example of what a Side A/Side B pair actually looks like or why polarity
would mislead a directional reader. A reviewer encountering this framing
for the first time has to do real work to see why the distinction matters,
which raises the risk of the "this task is artificial" objection (Section
4, item 1) landing before the reader reaches the formal defense.

**Recommended fix:** Add one short concrete illustration — even a single
sentence describing a hypothetical pair (e.g., a buffer-overflow-vulnerable
function and its patched counterpart, rendered once as a forward diff and
once as a reverse diff, with the candidate-identity question being "which
state is riskier" independent of which rendering the model sees) would let
a reader ground the formal notation immediately.

**New evidence needed:** No — this is an illustrative example, not a claim
requiring new data.

### 3.4 Repair decomposition opens abruptly (Medium)

**Why it matters:** Section 6 begins "We separate two claims that are easy
to conflate" with no sentence connecting back to the side-order failure
problem Sections 1-4 established. A reader following the paper's argument
linearly experiences a topic switch rather than the paper's intended
second act (having isolated *what* drives the failure, now ask whether it
can be *repaired*). This is a flow problem, not a content problem — the
technical content of Section 6 is otherwise sound (Section 2 of this
audit).

**Recommended fix:** Add one bridging sentence at the start of Section 6,
e.g., "Given that side-order failure is driven by presentation structure
rather than content, we ask whether it can be repaired structurally."

**New evidence needed:** No.

### 3.5 SaTML-specific framing is absent from the draft text (Medium)

**Why it matters:** The draft's "Open Submission Requirements" section
names SaTML 2027 as the target, but the paper's own Introduction and
Abstract contain no language connecting the contribution to SaTML's stated
scope (secure and trustworthy ML). As written, the draft could be
submitted almost anywhere in the security/ML-evaluation space without
edit — which is not wrong, but it means the paper does not yet make the
positive case for *why this venue specifically* should care, which
directly feeds reviewer objection 8 in Section 4 ("Why SaTML?").

**Recommended fix:** Add a clause to the Introduction connecting the
claim-boundary discipline (behavioral evidence, not internal-mechanism
proof; structural-vs-learned repair) to SaTML's trustworthy-ML framing
explicitly, rather than leaving the connection implicit.

**New evidence needed:** No — this is positioning language, not a new
claim.

### 3.6 Abstract is dense (Medium)

**Why it matters:** The abstract packs all six required points (Section 2
of `paper/workshop_short_paper_outline.md`) into a single 179-word
paragraph with no internal structure. It is within the word-count target
and does deliver every required point accurately, so this is a polish
issue rather than a comprehension blocker on the scale of 3.1-3.3 — but a
dense abstract is the first thing every reviewer reads, so it is worth
listing even at lower severity than the body-text issues above.

**Recommended fix:** Consider one internal sentence break (e.g., after the
mechanism-decomposition sentence, before the CrossVul sentence) to give the
reader a breath point. This does not require shortening the abstract, only
restructuring it.

**New evidence needed:** No.

### 3.7 Introduction assumes some background (Low-Medium)

**Why it matters:** This substantially overlaps with 3.2 and 3.3 rather
than being a separate defect — the Introduction's brevity is appropriate
for a workshop paper, and the actual gaps (no positioning sentence, no
concrete example) are already captured above with their own fixes. Listed
separately only because it was one of the candidate issues this audit was
asked to examine; no additional fix is needed beyond 3.2 and 3.3.

**New evidence needed:** No.

### 3.8 Figure/table placeholder count (Low — not currently a problem)

**Why it matters:** Five figure/table placeholders across an ~8-page target
is within normal range for a workshop paper, not excessive. This audit
considered whether to flag it as a weakness and concluded it is not one on
its own — the real issue is Table 3's *absence*, not the other five items'
presence. See Section 5 for the full per-item recommendation.

**New evidence needed:** No.

### 3.9 Page length is unvalidated (Low severity as a "weakness" — already honestly disclosed)

**Why it matters:** True, but the draft already states this itself in the
top-of-document status note and in "Open Submission Requirements" — it is
a disclosed open item, not a hidden defect. It cannot be fixed by editing;
it requires a PDF build path that does not yet exist
(`docs/PREPRINT_PREPARATION_PLAN.md` Section 3). Treated fully in Section 7
of this audit rather than as an editing weakness here.

**New evidence needed:** No — this needs tooling (a PDF build path), not
evidence.

## 4. Reviewer Risk Analysis

| # | Objection | Risk level | Draft's current defense | What to improve | New experiments needed? |
| --- | --- | --- | --- | --- | --- |
| 1 | "This task is artificial." | Medium | Section 2's formal candidate-identity vs. directional-patch distinction is accurate and matches `paper/draft_v0.md` §3 exactly | Add the concrete example (Section 3.3 above) so the defense lands before a reader has to parse formal notation | No |
| 2 | "This is just prompt sensitivity." | Medium-High | Section 4's label-only-vs-polarity-only decomposition already rebuts this implicitly — a generic prompt-sensitivity story would predict *both* interventions disrupt the prediction, but only the polarity one does | The rebuttal is present but never stated by name; add one clause explicitly naming and dismissing the prompt-sensitivity reading, since the evidence to do so is already in the same paragraph | No — the evidence already exists and is arguably the draft's strongest single result |
| 3 | "Only two model families." | Medium | Section 7 states the bounded-generality claim directly ("broader than one model but is not a universality claim") | The full paper's low-canonical stress-replication evidence (distilgpt2, a small generative judge — `paper/draft_v0.md` §6.2) is not mentioned at all in this draft; one sentence noting that broader, lower-canonical coverage exists would preempt this objection cheaply using evidence already collected | No — the evidence exists in the full paper, just not summarized here |
| 4 | "The mechanism claim is not internal." | Low | Already explicit in three places (Abstract, Section 4, Section 7): "behavioral... not a proven shared mechanism" / "not an internal-mechanistic proof" | None needed | No |
| 5 | "CrossVul confounds weaken the benchmark." | **High** | Section 5 contains the correct PrimeVul-vs-CrossVul contrast, but as six numbers in dense prose with no table (Section 3.1 above) | Restore a reduced Table 3 or restructure the prose into a parallel construction — the content of the defense is sound, only its legibility is not | No — the evidence already exists and already appears in the body; this is purely a presentation fix |
| 6 | "Repair result is mostly structural." | Low-Medium | Section 6 states the structural-vs-learned distinction with both p-values (`p=0.002` in-distribution, `p=0.508` on CrossVul, 0/5 nuisance families) | The abrupt section opening (Section 3.4 above) means this defense arrives without context; the bridging sentence fix there also helps this objection land in context | No |
| 7 | "This is not a deployable security tool." | Low | Section 7 agrees explicitly and reframes as the study's intended scope, not a limitation being defended | None needed | No |
| 8 | "Why SaTML?" | Medium | **None currently in the paper text** — the SaTML target only appears in the meta "Open Submission Requirements" section, which is not part of the actual paper body | Add explicit trustworthy-ML framing to the Introduction (Section 3.5 above), connecting the claim-boundary discipline to SaTML's stated scope | No — this is positioning language, not a new claim |

**Highest-risk objection: #5 (CrossVul confounds).** It is the only one
where the underlying defense is sound but its current presentation could
plausibly fail to land with a reviewer reading at normal speed — every
other objection either has a clean existing defense (1, 4, 6, 7) or a
cheap, evidence-already-exists fix (2, 3, 8).

## 5. Figure/Table Audit

| Item | Decision | Reasoning |
| --- | --- | --- |
| Figure 1 | **Remain in body** | Cheap, effective thesis motivation in the introduction; no issue found |
| Figure 5 | **Remain in body** | Carries the headline mechanism result; required | Optional v1+ consideration: could merge with Table 2 into one compact figure-with-inline-numbers to save space, but this is not required and should not be done before the text itself stabilizes |
| Table 2 | **Remain in body** | Pairs with Figure 5; required |
| Figure 7 | **Remain in body** | Carries the second major contribution (structural-vs-learned repair); required. Same optional merge-with-Table-4 consideration as Figure 5/Table 2, same caveat |
| Table 4 | **Remain in body** | Pairs with Figure 7; required |
| Figure 6 (currently supplement) | **Stay in supplement — do not return** | Section 3.1's fix for CrossVul-section readability is better served by a table (dense numeric contrast, needs to be scannable) than a chart; adding Figure 6 back would spend page budget without solving the actual problem found |
| Table 3 (currently supplement) | **Return a reduced version to body — this is a change from the prior plan** | This is this audit's most consequential figure/table finding: `paper/workshop_short_paper_outline.md` Section 5 recommended moving Table 3 to supplement while keeping its key contrast in prose, and the current draft executed that plan correctly — but reading the *result* shows the prose-only version is genuinely hard to parse (Section 3.1). A reduced 2-row table (crude-shortcut canonical accuracy; model-vs-shortcut agreement) restores legibility without the full four-row original. This is not a contradiction of the outline's reasoning, it is new evidence from actually reading the executed draft — exactly the kind of finding a fresh audit should surface rather than rubber-stamp |

Net effect on figure/table count if this recommendation is taken: six items
in body (five original plus a reduced Table 3) instead of five. This is a
modest increase, not a page-budget red flag on its own (Section 7), but it
should be weighed against Section 7's cut list if the eventual PDF build
shows the paper running long.

## 6. Citation and Anchor Audit

| Check | Result |
| --- | --- |
| No new `[RESULT: ...]` anchors | **Confirmed.** All 7 anchors used in `paper/workshop_draft_v0.md` (`polarity-gold-confound`, `primevul-progressive-controls`, `qwen-label-only-swap`, `qwen-polarity-only-swap`, `codebert-label-polarity-replication`, `crossvul-polarity-gold-confound`, `antisymmetric-repair`) are a subset of the anchors already in `paper/draft_v0.md`; zero new anchors were introduced. |
| All result anchors resolve to `paper/result_anchor_map.md` | **Confirmed.** All 7 anchors used have a corresponding row in the map. |
| All related-work anchors resolve to `paper/references.md` | **Confirmed.** All 10 `[RELATED: ...]` anchors used (`primevul`, `diversevul`, `codexglue`, `qwen25-coder`, `codebert`, `checklist`, `counterfactual-augmentation`, `deltasecommits`, `patcheval`, `crossvul`) exist as real entries in `paper/references.md`. |
| Citations sufficient for a workshop draft | **Mostly yes, one gap found.** Benchmark/dataset citations (PrimeVul, DiverseVul, CodeXGLUE, DeltaSecommits, PatchEval, CrossVul) and model citations (Qwen2.5-Coder, CodeBERT) are all present and correctly placed. The one gap: Section 7's discussion of evidence localization and abstention has no citation, even though `paper/references.md`'s "Evidence Localization and Explanation Faithfulness" section (`eraser`, `attention-not-explanation`, `attention-not-not-explanation`) exists and is cited for exactly this purpose in `paper/draft_v0.md` §2.4. Adding one citation clause there would ground that discussion the same way the rest of the draft is grounded. This is a minor gap, not a blocking one. |
| No citation should be fabricated | **Confirmed.** Every anchor used was checked against the actual text of `paper/references.md` in this audit (not assumed); none were invented. |

## 7. Page-Budget Audit

**No PDF build path exists yet, so this is qualitative only — no claim of
actual page fit is made here**, consistent with `docs/PREPRINT_PREPARATION_PLAN.md`
Section 3's still-unresolved PDF blocker and this draft's own top-of-document
disclosure.

As a rough signal, not a validated measurement: the Abstract plus the seven
body sections total approximately 1,300 words of prose, before accounting
for the five (soon to be six, if Section 5's Table 3 recommendation is
taken) figure/table placeholders, which each consume real page space once
typeset. At typical two-column academic density, prose of this length
alone is well under a 5-12 page range; the figures and tables are the
larger unknown, since their typeset size depends on decisions (single- vs.
multi-column figures, table font size) that have not been made.

**Classification: likely within target**, not "likely too long" and not
fully "unknown until typeset" — there is enough signal from the word count
and figure/table count to lean toward a positive estimate, but this
classification should be re-confirmed once a PDF build path exists
(`docs/PREPRINT_PREPARATION_PLAN.md` Section 6) and once SaTML 2027's own
page limit is confirmed (this audit's own recurring caveat).

**If the eventual typeset version runs over length, recommended cut order:**

1. The Section 3 benchmark-diagnosis motivating sentence (already minimal,
   but could compress to a clause).
2. Merge Figure 5 with Table 2, and/or Figure 7 with Table 4, into single
   compact items (flagged as optional in Section 5, would become the first
   real cut if space is tight).
3. The reduced Table 3 this audit recommends adding (Section 5) — if page
   budget cannot absorb it, fall back to the prose-only version the current
   draft already has, accepting the CrossVul-readability cost documented in
   Section 3.1 as a lesser evil than exceeding the page limit.

Do not cut the responsible-use paragraph, the claim-boundary paragraph, or
any of the seven `[RESULT: ...]`-anchored numeric claims to save space —
none of those are candidates for compression under any length pressure.

## 8. What Should Change in v1

**Top 5 edits**, each already justified in Section 3 above:

1. Add a concrete candidate-identity example (Section 3.3).
2. Add the missing related-work positioning sentence the Supplement Note
   already promises (Section 3.2).
3. Fix CrossVul-section legibility — reduced Table 3 return to body or
   prose restructure (Section 3.1, Section 5).
4. Add a bridging sentence at the start of the repair section (Section 3.4).
5. Add explicit SaTML/trustworthy-ML framing to the Introduction
   (Section 3.5).

**What to cut:** Nothing, in this pass. The page-budget audit (Section 7)
classifies the draft as likely within target; cutting preemptively without
a confirmed page limit risks removing content that turns out to fit.

**What to clarify:** The candidate-identity task (edit 1), the CrossVul
confound section (edit 3), and the repair section's opening (edit 4) — all
three are content-correct but access-limited in their current form, which
is a different failure mode than being wrong, and the fix is clarification,
not correction.

**What to move to supplement:** Nothing new. If anything, this audit's
Table 3 recommendation moves content *toward* the body, not away from it —
a genuine departure from the outline's original compression direction, made
because reading the executed draft surfaced a real readability cost the
original compression plan did not anticipate.

**What not to touch:** The one-sentence thesis; the Claim Boundaries
paragraph; the Open Submission Requirements note; the existing seven
`[RESULT: ...]` anchors and ten `[RELATED: ...]` anchors (correct as used,
Section 6); the responsible-use paragraph in Section 7 of the draft
(already matches `paper/draft_v0.md` §9 verbatim in substance and should
not drift from it). None of these have a finding against them anywhere in
this audit.

## 9. What Not to Do Next

- **Do not run new experiments yet.** Every fix this audit recommends
  (Section 8) is presentational, structural, or positioning work using
  evidence that already exists — none require new data.
- **Do not submit anywhere yet.** SaTML 2027's own submission requirements
  remain unpublished (Section 1), independent of the draft's text quality.
- **Do not create the PDF before v1 text stabilizes.** Typesetting text
  that is about to change under the Section 8 edit plan wastes the
  typesetting effort; sequence v1 first.
- **Do not anonymize before SaTML 2027's requirements are published.**
  This draft's anonymization strategy is currently planned against SaTML
  2026's historical precedent only (`docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md`);
  anonymizing against an unconfirmed policy risks doing the work twice.
- **Do not add claims to make the draft sound stronger.** None of the
  weaknesses this audit found (Section 3) are evidence gaps — they are
  clarity, positioning, and presentation gaps. The correct fix for every
  one of them is better exposition of evidence that already exists, never
  a stronger-sounding sentence unsupported by that evidence. This audit
  found no place where the draft's claims exceed what `paper/draft_v0.md`
  supports, and v1 should preserve that property exactly, not erode it in
  the process of trying to sound more persuasive.

## 10. Recommended Next PR

**Recommendation: `paper: revise workshop draft v1`.**

This audit's own instruction was to choose this option only if v0 is found
structurally sound enough to revise directly, rather than fragmented into
several narrow single-issue PRs. That condition is met: Section 1's verdict
is "ready for internal editing," Section 3's five weaknesses are all
clarity/positioning fixes rather than structural defects, and Section 4
found no reviewer objection lacking a real defense — only objections whose
existing defense needs better exposition. The five weaknesses in Section 3,
the Table 3 figure/table change in Section 5, and the minor citation gap in
Section 6 are textually adjacent (they touch the Introduction, Section 2,
Section 5, and the start of Section 6 — a contiguous stretch of the same
short document) and are more efficiently implemented together in one
coherent revision pass than as separate PRs each touching overlapping
sections of the same file.

The alternative narrower options considered — `paper: add concrete
candidate-identity example`, `paper: tighten workshop introduction`,
`paper: simplify CrossVul confound explanation`, `paper: revise
figure/table plan` — each correspond to exactly one of Section 3's
findings. Splitting them would mean four to five separate PRs each
re-reading and re-touching the same ~1,300-word document, with no
independent value in landing them separately: none of the five edits
depends on external confirmation (unlike, say, the SaTML CFP dependency
elsewhere in this project's targeting work), so there is no sequencing
reason to split them. A single `paper: revise workshop draft v1` PR that
implements all five Section 8 edits, the Section 5 figure/table change, and
the Section 6 citation addition is the highest-leverage next step.
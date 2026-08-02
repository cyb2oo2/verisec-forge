# Workshop / Preprint Targeting Plan

This document answers one question: **what kind of workshop / preprint
audience is the best fit for this project, and how should the current paper
be positioned for external research feedback?** It is a targeting and
positioning plan, not the preprint itself, not a workshop submission, and
not a rewrite of `paper/draft_v0.md`. It does not run experiments, train or
tune models, change the thesis, add new results, or rewrite the paper into
promotional prose.

It builds on `docs/PREPRINT_PREPARATION_PLAN.md` (the preprint-readiness
plan) rather than duplicating it. That document already established: the
draft is complete, citation gaps are closed, the external review packet is
packaged, and public preprint posting has a short list of true remaining
blockers. This document adds the piece that plan deliberately left as a
human action rather than a checklist item: *how* to actually get external
research feedback, through which channel, and with which paper shape.

## 1. Goal of This Line

**This is not another self-audit.** The project has already produced several
internal readiness audits (`docs/REVIEWER_READINESS_AUDIT.md`,
`docs/PREPRINT_PREPARATION_PLAN.md`), and each of them independently
concluded the same thing: the highest-leverage remaining step is contact
with the outside research world, not another internally-produced document.
This plan exists to make that contact concrete and actionable, not to add a
third audit to the pile.

**The goal is to get real external research feedback by entering a relevant
research channel.** Three mechanisms, not one:

1. **Workshop submission.** A paper (or short-paper/extended-abstract
   version) submitted to a workshop whose scope matches this project's
   content, subject to actual peer review by people outside the project.
2. **Preprint release.** Posting `paper/draft_v0.md` (once built to a
   submittable format, per `docs/PREPRINT_PREPARATION_PLAN.md` Section 6) to
   a public preprint server, making it findable and citable.
3. **Targeted sharing with workshop/community researchers.** Sending the
   draft, or a link to it, to specific researchers already working in the
   matched subfield — not a broadcast, a targeted handoff to people whose
   feedback would actually be informative.

**These three mechanisms are not interchangeable, and conflating them is
the single most common mistake in this kind of planning.** This plan draws
the distinction explicitly and holds it throughout:

- **Workshop review is external feedback.** It is the only one of the three
  mechanisms that comes with a structural guarantee that someone outside
  the project will read the paper closely and generate a documented
  reaction (accept, reject, or reviewer comments) within a bounded
  timeframe. This is the closest available substitute for the "one
  qualified person reads the draft and reacts" step every prior audit
  identified as the actual blocker.
- **Preprint posting is visibility, not review.** Posting a preprint makes
  the work findable, citable, and timestamped. It does not guarantee anyone
  reads it, and it carries no structural mechanism for feedback to come
  back to the author. Treating a preprint post as if it were equivalent to
  peer feedback is the mistake this document is designed to prevent.
- **Cold PI outreach emails are optional, not the main mechanism.** The
  templates already exist (`docs/EXTERNAL_REVIEW_EMAIL_TEMPLATE.md` Version
  B), and sending one is a legitimate use of that packet, but it depends on
  an individual's discretionary time and has a much lower and much less
  predictable response rate than a workshop's structural review process.
  This plan treats cold outreach as a parallel, low-cost option alongside
  workshop submission — not a replacement for it, and not the primary route.

## 2. Current Artifact Readiness

Current status, each item traceable to a real artifact:

| Item | Status | Evidence |
| --- | --- | --- |
| Working draft exists | Complete | `paper/draft_v0.md` — Abstract through Discussion, Appendices A-E, no placeholder text (`docs/PREPRINT_PREPARATION_PLAN.md` Section 2) |
| Citation gaps resolved | Complete | `paper/references.md` — "No citation gaps remain as of this pass," enforced by `tests/test_paper_citation_polish.py` |
| External review packet exists | Complete, not yet sent/returned | `docs/EXTERNAL_REVIEW_REQUEST.md`, `docs/EXTERNAL_FEEDBACK_PACKET.md`, `docs/EXTERNAL_REVIEW_EMAIL_TEMPLATE.md` |
| Preprint preparation plan exists | Complete | `docs/PREPRINT_PREPARATION_PLAN.md` — full 12-section plan, verdict NOT READY for public posting pending 3 blockers |
| Public preprint posting still has remaining items | True, unchanged by this plan | `docs/PREPRINT_PREPARATION_PLAN.md` Section 3: no external human has read the draft, `CITATION.cff` has a placeholder author, no PDF build path exists |
| No new experiments required before targeting | True | `docs/PREPRINT_PREPARATION_PLAN.md` Section 3 classifies all real blockers as process/packaging gaps, not evidence gaps; this plan inherits that conclusion and adds no new evidence requirement |

**Readiness classification for the three channels this plan is about:**

| Channel | Readiness | Why |
| --- | --- | --- |
| Private feedback (cold PI email / targeted sharing) | **READY** | The packet (`docs/EXTERNAL_REVIEW_REQUEST.md`, `docs/EXTERNAL_REVIEW_EMAIL_TEMPLATE.md`) is complete, claim-bounded (verified by `tests/test_external_review_packet.py`), and requires no further drafting to send today. |
| Workshop submission | **READY WITH CAVEATS** | The scientific content is workshop-ready (see Section 3), but the *paper itself* — as `paper/draft_v0.md` currently stands, at roughly 10 in-draft sections plus five appendices — is shaped as a full technical report, not a workshop-length submission. A compression/adaptation pass (Section 6) is needed before any specific workshop's page limit can be met; this plan defines that pass without performing it. Author metadata (the `CITATION.cff` placeholder, also flagged in `docs/PREPRINT_PREPARATION_PLAN.md`) must also be resolved before a real submission, since workshop submission systems require real author records even under double-blind review. |
| Preprint posting | **NOT READY** | Unchanged from `docs/PREPRINT_PREPARATION_PLAN.md` Section 1: no external human has read the draft, author metadata is a placeholder, and no PDF build path exists. This plan does not relitigate that verdict — see Section 10 for how this plan's recommendation interacts with it. |

## 3. Candidate Audience Categories

Grounded against real, currently-identifiable venues in each category (see
Section 8 for the search protocol and the caveat on deadline currency —
several named below already had their 2026-cycle deadline close by the time
of this plan and are cited as *type examples*, not live targets).

### 3.1 ML Evaluation / LLM Evaluation Workshops

*Type examples: NeurIPS Evaluations & Datasets Track (a full conference
track, not a workshop, but the closest scope match found); general
benchmark-critique workshops at ICML/ICLR/NeurIPS.*

| Dimension | Assessment |
| --- | --- |
| Fit with the project | Strong. NeurIPS 2026's Evaluations & Datasets Track explicitly solicits "work that analyzes strengths, limitations, or failure modes of existing benchmarks or evaluation practices" — close to a direct description of this paper's benchmark-diagnosis and confound-measurement content (Sections 5, 6.4). |
| What they would value | VeriPatch-RR as a reusable relational evaluation instrument; the CrossVul confound finding (a benchmark-validity result); the negative-control discipline (metadata-only, candidate-only, counterpart-only near-chance); the claim-boundary rigor itself, which this reviewer community specifically rewards. |
| What they might criticize | Thin security-domain framing relative to an ML-evaluation crowd's usual generality expectations; may ask "why security specifically, why not a broader code task" or push for more model families to argue the *evaluation instrument* generalizes, not just the finding. |
| Reframing needed | Moderate. Lead with the evaluation-instrument and methodological-lesson framing (pointwise accuracy can hide relational failure, generally); keep the security application as the domain, not the headline. |
| Extra experiments required | None to submit; a broader-model-coverage request is a plausible revision ask, not a submission blocker. |
| Rejection/misunderstanding risk | Medium — chiefly the risk of being read as "a security paper in the wrong room" if the framing isn't adjusted toward evaluation methodology first. |

### 3.2 AI for Code / Code Generation Workshops

*Type examples: LLM4Code (3rd edition ran at ICSE 2026); DL4C (Deep
Learning for Code, 5th edition ran at ICML 2026, historically
ICLR-affiliated before that).*

| Dimension | Assessment |
| --- | --- |
| Fit with the project | Very strong, close to a direct topical match. LLM4Code 2026's own published scope lists "program repair, vulnerability detection, code comprehension, refactoring, datasets/evaluation methods" — nearly a verbatim description of this paper's content. |
| What they would value | The label-vs-polarity mechanism decomposition; the antisymmetric structural repair attempt; the honest negative result on the learned fine-tuning repair; the reproducibility artifacts (manifests, pure-counting reproduction scripts). |
| What they might criticize | This venue type often skews toward generative/agentic code models; reviewers may ask why the evaluation is classification-based rather than testing generation/agentic repair models directly, or see the candidate-identity vs. directional-patch distinction as a fine-grained academic point that needs a sharper one-sentence explanation. |
| Reframing needed | Light. This venue type's scope already matches closely; the main work is compression (Section 6), not reframing. |
| Extra experiments required | None required; a code-generation-model data point is a plausible stretch request but not typically blocking at workshop tier. |
| Rejection/misunderstanding risk | Low-to-medium. Main risk is reading as "another shortcut-detection paper" unless the relational-consistency framing (not just shortcut detection) is foregrounded in the first paragraph. |

### 3.3 Software Engineering / Program Repair Workshops

*Type examples: ICSE-affiliated Automated Program Repair workshops;
ICSE SVM (Software Vulnerability Management, more practitioner-facing than
strictly APR).*

| Dimension | Assessment |
| --- | --- |
| Fit with the project | Moderate-to-weak for a strict automated-program-repair (APR) audience, stronger for the vulnerability-management framing. This paper does not generate patches; it decides which side of an existing pair is riskier, and its "repair" (Section 8) is a structural readout constraint plus an unresolved learned objective, not a working patch-generation system. A strict APR program committee's core expectation — a system that produces patches — is not what this paper offers. |
| What they would value | The shortcut-diagnosis rigor (progressive negative controls); the candidate-identity task as a precursor question worth answering before directional patch-repair evaluation is trustworthy; the reproducibility discipline, unusually strong relative to typical APR submissions. |
| What they might criticize | "This isn't program repair, it's classification/evaluation" as a scope objection; the repair section's honest null result may read as underwhelming to an audience expecting demonstrated patches. |
| Reframing needed | Substantial. Would need to lead with a "toward trustworthy program-repair evaluation" framing and state up front that this is a diagnostic/evaluation contribution, not a repair-generation system, to preempt the scope mismatch. |
| Extra experiments required | None strictly, but a strict-APR program committee may consider the paper out of scope regardless of framing — this is a venue-fit risk framing cannot fully resolve. |
| Rejection/misunderstanding risk | Medium-to-high for strict APR workshops (real desk-reject risk on scope); lower for the SVM-style vulnerability-management framing, which is closer to Section 3.4 below. |

### 3.4 Security / Vulnerability Analysis Workshops

*Type examples: LLM4Sec (2nd edition, ESORICS 2026); LAST-X — LLM Assisted
Security and Trust Exploration (NDSS 2026); ICSE SVM.*

| Dimension | Assessment |
| --- | --- |
| Fit with the project | Strong on application domain. LAST-X's published scope explicitly includes "LLM-assisted code-analysis and verification" and "case studies and practical applications of LLMs in real-world software development and testing" — a direct match for this paper's core content. |
| What they would value | The CrossVul confound as a concrete, actionable "don't trust this benchmark's headline number" warning; the explicit "not a deployed scanner" framing, which aligns with a security audience's practiced skepticism of overclaiming AI security tools; the diff-hunk-polarity mechanism as a concrete presentation-shortcut warning relevant to real patch-review tooling design. |
| What they might criticize | Security venues often want a sharper attack/defense or concrete-tool angle; may ask "so what should a security team do differently tomorrow" more insistently than an ML-evaluation audience would, and may probe the real-world-deployment-relevance gap given the paper's own explicit non-deployment framing. |
| Reframing needed | Moderate. Foreground the practical security implication (why relational consistency matters for real patch-review workflows) ahead of the evaluation-instrument mechanics. |
| Extra experiments required | None for evaluation/case-study-oriented workshops (LLM4Sec, LAST-X both explicitly solicit this kind of work per their published scope); the more practitioner-facing SVM would expect heavier operational framing. |
| Rejection/misunderstanding risk | Low-to-medium for LLM4Sec/LAST-X given their published scope match; higher for SVM absent the vulnerability-management reframing. |

### 3.5 AI Safety / Model Behavior Audit Workshops

*Type examples: SaTML — IEEE Conference on Secure and Trustworthy Machine
Learning; general trustworthy-ML or mechanistic-interpretability workshops.*

| Dimension | Assessment |
| --- | --- |
| Fit with the project | Strong for SaTML-style trustworthy/secure-ML framing — the paper's own title uses "Auditing," and its central claim-boundary discipline (behavioral evidence, not internal-mechanism proof) is exactly SaTML's kind of contribution. Weaker for a strictly mechanistic-interpretability-focused workshop specifically. |
| What they would value | The claim-boundary discipline itself (explicitly not claiming a shared internal mechanism); the honest negative result on the learned repair; the antisymmetric structural-constraint result as a genuine, if partial, mitigation. |
| What they might criticize | A mechanistic-interpretability-leaning reviewer may push for actual internal evidence (probing, activation patching) that this paper explicitly disclaims having; "behavioral only" could read as a weakness rather than an honest scope boundary to that specific sub-audience. |
| Reframing needed | Light-to-moderate for SaTML-style trustworthy-ML framing (close fit already); would be substantial-to-infeasible for a strict mechanistic-interpretability workshop, which is arguably a poor fit outright rather than a reframing problem. |
| Extra experiments required | None for SaTML/trustworthy-ML broadly. A mech-interp-specific workshop's implicit expectation of probing/activation evidence is not something this plan recommends adding just to fit that narrower audience. |
| Rejection/misunderstanding risk | Low for SaTML-style venues (strong natural fit); medium-to-high specifically for mechanistic-interpretability workshops, where the evidence bar mismatch is structural, not framing-fixable. |

### 3.6 Empirical Software Engineering Venues

*Type examples: MSR (Mining Software Repositories); ESEM (Empirical
Software Engineering and Measurement).*

| Dimension | Assessment |
| --- | --- |
| Fit with the project | Moderate. The paper has real empirical-SE methodological bones — progressive negative controls, disjoint-split stress evaluation, bootstrap confidence intervals, and dataset-artifact diagnosis are all empirical-SE hallmarks — but empirical-SE venues typically expect either a large-scale mining study or a more classical human-subject/qualitative design, and this paper is closer to a controlled ML-behavioral-audit study that happens to use SE data. |
| What they would value | The dataset-artifact diagnosis (same-source PrimeVul accuracy collapsing under negative controls) is a benchmark-validity finding empirical-SE reviewers recognize well; the reproducibility discipline matches MSR's registered-reports and artifact-evaluation culture closely. |
| What they might criticize | May read as "an ML paper using SE data" rather than an SE paper; may want the traditional explicit research-question structure (RQ1/RQ2/RQ3) and an SE-style threats-to-validity section, neither of which the current draft uses in that exact form. |
| Reframing needed | Substantial. Restructuring toward explicit SE research questions and empirical-SE conventions is a bigger lift than the ML/security venues in 3.1-3.5 require. |
| Extra experiments required | None strictly required, but MSR-style reviewers may expect a larger-scale mining component this paper does not have (it is controlled-experimental, not a large-scale repository mining study) — a plausible source of reviewer friction, not a hard blocker. |
| Rejection/misunderstanding risk | Medium-to-high. Genuine scope-fit uncertainty; empirical-SE reviewers unfamiliar with ML-behavioral-audit framing may not have a ready rubric for evaluating it. |

### 3.7 Preprint-Only Public Release

| Dimension | Assessment |
| --- | --- |
| Fit with the project | Universal — no program committee, so no scope-fit question in the workshop sense. |
| What they would value | Not applicable in the same sense; there is no reviewer, only self-selected readers. |
| What they might criticize | No formal review exists to raise or resolve criticism before the fact; any of the concerns in 3.1-3.6 could surface as unmoderated public comment instead, with no bounded timeframe and no structural guarantee of a response. |
| Reframing needed | None required by the mechanism itself, but `docs/PREPRINT_PREPARATION_PLAN.md`'s three blockers (author metadata, PDF build, external read) still apply before posting. |
| Extra experiments required | None. |
| Rejection/misunderstanding risk | "Rejection" does not apply, but **misunderstanding risk is arguably highest here**: there is no reviewer positioned to correct a wrong first impression before it becomes public and effectively permanent. This is precisely why Section 1 insists preprint posting is visibility, not review, and should not substitute for it. |

## 4. Best-Fit Positioning

Choosing the top two from Section 3 by the same criteria the section
already applied — fit, reframing cost, and rejection risk — plus one factor
Section 3 deliberately left to this section: whether a real, near-term
venue instance actually exists (that is a timing question, addressed fully
in Sections 8-9, but it tips the choice between two otherwise-close
categories here).

### Positioning A

**Audience:** AI for Code / Code Generation workshops (Section 3.2) — type
example LLM4Code (ICSE-affiliated), with DL4C as a secondary instance of
the same category.

**Core framing:** "A relational evaluation instrument for secure-patch
models: pointwise code-model accuracy can hide relation-violating behavior,
and we show why, through a controlled mechanism decomposition."

**Why it fits:** LLM4Code's own published scope — program repair,
vulnerability detection, code comprehension, datasets/evaluation methods —
is close to a direct description of this paper's content, not an analogy
reached for. This is the tightest scope match found in Section 3.

**What to emphasize:** VeriPatch-RR as a reusable relational evaluation
instrument; the label-vs-polarity mechanism decomposition (Section 6.3);
the cross-architecture Qwen/CodeBERT behavioral replication; the
reproducibility artifacts (manifests, pure-counting reproduction scripts) —
this reviewer community specifically rewards that discipline.

**What to downplay:** the security-application framing as the sole
motivation — keep it as the concrete instantiation of a general
evaluation-methodology point, not the headline; do not apologize for the
repair section's negative result, frame it as a methodological finding
about what repair evaluation requires, which is itself a contribution to
this audience.

**Likely reviewer attack:** "This is classification, not generation — why
not evaluate an actual code-generation or agentic repair model directly
attempting the patch-review task?"

**How to defend:** The candidate-identity task boundary (`paper/draft_v0.md`
Section 3) is a stated, deliberate scope choice, not an oversight — it
isolates the relational-consistency question cleanly before layering
generation on top. State this directly rather than defensively, and name
generation-model evaluation as a natural, explicitly bounded follow-up
direction rather than a gap being hidden.

### Positioning B

**Audience:** Security / Vulnerability Analysis workshops (Section 3.4) —
type examples LLM4Sec (ESORICS-affiliated) and LAST-X (NDSS-affiliated).

**Core framing:** "Why a security-patch model's high pointwise accuracy can
still be untrustworthy for real patch review: a presentation-structure
shortcut, not detection capability."

**Why it fits:** LAST-X's published scope explicitly covers "LLM-assisted
code-analysis and verification" and "case studies and practical
applications of LLMs in real-world software development and testing" — a
close match to this paper's application domain. Critically, at least one
venue in this category (LLM4Sec at ESORICS 2026, Rome, Sep 14-18 2026)
could not be confirmed as closed by this plan's research (Section 9) —
its parent conference is still months out, unlike Positioning A's and
most of Section 3's other type examples, which were confirmed closed.
This is a reason to check it first, not a claim that it is open; the exact
deadline must be verified against its official CFP page (Section 8) before
being treated as a live target.

**What to emphasize:** the CrossVul confound as a concrete, actionable
"don't trust this benchmark's headline number" warning; the explicit
"not a deployed scanner" framing, which reads as credible discipline to a
security audience practiced at discounting overclaimed AI security tools;
the diff-hunk-polarity mechanism as a concrete presentation-shortcut
warning relevant to real patch-review tool design.

**What to downplay:** the evaluation-instrument statistical machinery
(pair-cluster bootstrap, McNemar tests, marginal-conditioned baselines) —
keep these at appendix-reference level rather than the lead; a
security-practitioner-leaning reviewer cares more about the implication
than the protocol.

**Likely reviewer attack:** "So what should a security team actually do
differently tomorrow? This reads as diagnostic-only, with no fix."

**How to defend:** Point to the antisymmetric structural readout
(`paper/draft_v0.md` Section 8) as a concrete, implementable partial
mitigation — side-swap equivariance holds by construction — while stating
plainly that the learned fine-tuning layer on top of it remains
unvalidated. There is a real, partial, honestly-bounded answer here; state
it as such rather than retreating to "diagnosis only."

### Primary Target Audience

**Positioning A (AI for Code / Code Generation workshops) is the primary
target**, on scope-fit grounds: it is the tightest match found in Section
3, requires the least reframing, and carries the lowest rejection risk of
any category evaluated. **Positioning B (Security / Vulnerability Analysis
workshops) is the parallel near-term track**, not a fallback — it should be
pursued concurrently given the LLM4Sec@ESORICS window this plan could not
confirm as closed (Section 9), rather than sequentially after Positioning
A — pending the Section 8 verification that window still requires. These are not
mutually exclusive: the underlying paper content supports either framing
with a different lead section and different emphasis, not a different
paper (see Section 6).

## 5. Workshop vs. Preprint Strategy

### Option A: Workshop First, Preprint Later

**Pros:** gets formal reviewer feedback; avoids locking public wording too
early; lets review comments improve the public version before it becomes
permanent.

**Cons:** slower; may miss the current deadline window for a given venue;
workshop acceptance is uncertain, and a rejection with no public artifact
yet can feel like a null outcome even though reviewer comments are still
real feedback.

**Project-specific note:** the two real venues found with double-blind
review requirements (LLM4Code, LAST-X — Section 3) create a concrete
constraint this option must respect: a public preprint should not be
posted before or during a specific double-blind submission's review
period at a venue whose policy treats that as a prior-publication or
anonymity violation. "Workshop first" therefore means literally first —
holding the preprint until after that venue's decision, not just
prioritizing workshop preparation.

### Option B: Preprint First, Workshop Later

**Pros:** establishes a public, citable timestamp; easier to share broadly;
faster for PhD/research signaling on a fixed application timeline.

**Cons:** no formal review; the public version may expose weaknesses before
anyone catches them; a reviewer encountering the work later may see an
unpolished version rather than the best version the workshop process could
have produced.

**Project-specific note:** per `docs/PREPRINT_PREPARATION_PLAN.md`, preprint
posting is currently **NOT READY** — three blockers (external read, author
metadata, PDF build) are unresolved. This option cannot actually execute
faster than Option A right now; it only looks faster in the abstract.

### Option C: Simultaneous Preprint + Workshop Submission

**Pros:** visibility plus review together; common practice in ML
communities where arXiv-alongside-double-blind-review is an accepted norm.

**Cons:** some workshops have anonymity or prior-publication policies that
this genuinely conflicts with; requires careful, venue-specific policy
checking rather than an ML-community-wide assumption.

**Project-specific note:** both concrete double-blind venues found in
Section 3 (LLM4Code: "not accepted or published elsewhere at the time of
submission"; LAST-X: "must not overlap with papers that are already
published or concurrently submitted to other venues") state policies whose
treatment of a *preprint specifically* (as opposed to a peer-reviewed
publication) is not spelled out in the CFP text this plan could access.
This is exactly the "requires careful venue-specific checking" risk named
in the option's own cons — it is not resolved by this plan and should not
be assumed favorably.

### Default Strategy

**Default: Option A — workshop first, preprint later.** Three reasons,
weighted in this order:

1. The project owner's stated goal is *real external research feedback*,
   and workshop review is the one mechanism (Section 1) that structurally
   guarantees it. A preprint alone does not serve that goal, however fast
   it is to post.
2. Preprint posting is not currently executable anyway (`docs/PREPRINT_PREPARATION_PLAN.md`
   Blockers 1-3) without first resolving the same author-metadata and
   external-read work that workshop preparation also requires — so Option
   B's speed advantage is not real under current conditions.
3. Two of the three concrete venues identified in Section 3 (LLM4Code,
   LAST-X) require double-blind review with a policy this plan cannot
   confirm tolerates a simultaneous public preprint. Option A avoids that
   risk entirely by construction; Option C would require resolving it
   venue-by-venue first.

**When another option would be better:**

- **Prefer Option B (preprint first)** if no workshop deadline is reachable
  within a reasonable window (for example, if the only live near-term venue,
  LLM4Sec@ESORICS, turns out to have already closed by the time this is
  acted on, and the next confirmed opportunity in any category is many
  months out) and a fixed external deadline — such as a PhD application
  cycle — makes the timestamp value of a preprint more urgent than the
  feedback value of waiting for review. This is a real, legitimate
  trade-off, not a fallback of last resort; it should be an explicit
  decision if it is made, not a default drifted into.
- **Prefer Option C (simultaneous)** only after a specific target venue's
  policy is confirmed, in writing on its own CFP page, to tolerate a
  concurrent public preprint alongside double-blind submission. Several
  NeurIPS-affiliated workshops are historically more preprint-tolerant than
  the security-conference-affiliated workshops found in this plan; if the
  eventual target shifts toward that category (Section 9), Option C becomes
  worth re-evaluating on its own merits.

## 6. What the Workshop Paper Should Look Like

This section defines the compression and adaptation the current draft would
need for a workshop submission. **No rewrite happens in this PR** — this is
a specification for a future `paper: create workshop short-paper outline`
PR (Section 11), not an edit to `paper/draft_v0.md`.

**Ideal page length.** The real venues found in Section 3 cluster around
6-10 pages of body text: LLM4Code accepts 4-8pp research papers (also 1-4pp
position papers and 1-5pp extended abstracts); LAST-X caps at 10pp excluding
bibliography and appendices; SaTML allows 5-12pp body text with unlimited
reference/appendix space. **Target roughly 8 pages of body text**, which
fits comfortably inside all three without wasting the available room. All
venues found treat appendices/supplementary material as effectively
uncapped, so compression should move detail to supplementary material
rather than delete it.

**Figures and tables to keep in the body.** The current draft has 7 figures
and 4 tables; an 8-page budget supports roughly 3 figures and 2 tables in
the body.

- Keep: Figure 1 (problem motivation — sets up the thesis in one image),
  Figure 5 (label-vs-polarity mechanism — the core finding), and Figure 7
  (repair decomposition — the second major contribution). Keep Table 2
  (mechanism decomposition) and Table 4 (repair decomposition) — these two
  tables carry the two headline results in compact form.
- Move to supplementary: Figure 2 (VeriPatch-RR transformation taxonomy),
  Figure 3 and Figure 4 (readout ablation/discovery-confirmation mechanism
  detail), and Table 1 (main results summary, mostly scaffolding —
  progressive controls and pair-coupled decoding — rather than the
  headline). Figure 6 and Table 3 (CrossVul confound) are a conditional
  case: keep them in the body if the submission targets Positioning B
  (Security workshops, where the confound is a headline point); move to
  supplementary if targeting Positioning A (AI for Code workshops, where it
  is supporting evidence for the broader thesis rather than the lead).

**Appendices to move to supplemental.** All five current appendices
(A Artifact Manifest, B Bootstrap and Significance Protocol, C Runtime
Visibility Schema, D Prompt and Output Contracts, E Result Anchor Map) are
protocol/reproducibility reference material appropriate for supplementary
material at workshop length, consistent with every venue found in Section 3
excluding appendices from the page cap. Keep a one-line pointer to each from
the body so a reviewer knows the reproducibility material exists without
needing to read it to evaluate the paper.

**Presenting the thesis in the first half-page.** The current Abstract plus
Introduction spreads the problem statement, central finding, and scope
boundary across roughly a full page. The workshop version should compress
this to three sentences occupying the first half-page: (1) the problem —
patch review is relational, but secure-code models are evaluated pointwise;
(2) the finding — a model's decision is nearly inert to swapping prose side
labels but collapses under a diff-hunk polarity flip with gold held fixed,
meaning presentation structure, not detection capability, drives the
failure; (3) the scope boundary — this is behavioral evidence across two
architectures, not an internal-mechanism claim, and not a deployed tool.
This is a compression of material that already exists in the draft, not new
content.

**How much repair evidence to include.** Compress Section 8 to: the
antisymmetric structural result (one headline accuracy figure with its
confidence interval) and the learned-repair negative result in one sentence
carrying both p-values (in-distribution significant, external-source and
nuisance-transform legs not significant). Move the full five-family
nuisance-transform breakdown and the per-family Bonferroni accounting to
supplementary. Figure 7 alone should carry the visual weight of this
section in the body.

**How much CodeBERT replication to include.** Keep — this is core evidence
for the claim boundary (behavioral replication across architectures, not a
shared-mechanism claim) and should not be cut. Compress by keeping the
Qwen-vs-CodeBERT comparison in Table 2's existing row format, and move the
separate crude-net-polarity-shortcut-agreement analysis (the `~0.57` vs.
`~0.96` PrimeVul comparison) to supplementary — it is a real and interesting
secondary nuance, not essential to the headline within an 8-page budget.

**Avoiding the benchmark-engineering-paper impression.** The current draft
carries substantial instrument-construction surface area (transformation
taxonomy, runtime-visibility/tokenizer accounting, prompt-contract
specification) that a reviewer skimming quickly could mistake for the
paper's main contribution, reading it as "another benchmark paper" rather
than an evaluation-methodology and mechanism-finding paper. The fix is
ordering, not deletion: lead the abstract and introduction with the
*finding* (the label-vs-polarity mechanism, the CrossVul confound) and
introduce VeriPatch-RR afterward as the instrument that made the
measurement possible, not as the headline contribution itself. This
directly matches Positioning A's emphasis guidance in Section 4.

**Making the contribution clear to reviewers.** The current draft's
Introduction lists five numbered contributions. For a workshop-length
version, trim to three: (1) the label-vs-polarity mechanism decomposition,
(2) the cross-architecture behavioral replication (Qwen and CodeBERT), and
(3) the structural-vs-learned repair distinction. Fold the relation-
preserving evaluation framing and the cross-source confound analysis into
supporting evidence for these three rather than listing them as separate
contributions — five contributions in an 8-page paper reads as diffuse to a
reviewer skimming quickly; three tightly-evidenced contributions reads as
sharp.

## 7. What Not to Claim

The claim boundary for workshop/preprint readers is the same boundary
`docs/PREPRINT_PREPARATION_PLAN.md` Section 4 already verified against the
draft text — restated here for a workshop-submission audience, in the same
negated form the draft itself already uses, so nothing below reads as a
bare assertion of the claim it is warning against.

**Do not claim:**

- that secure patch reasoning has been solved;
- that this is a deployed vulnerability scanner;
- a universal failure claim covering all models;
- proof of an internal mechanism;
- a learned repair claimed as validated or transferable;
- that this is a production-ready security tool;
- that the system replaces human review or a human reviewer;
- readiness for acceptance at a top-tier conference.

**Also avoid**, specifically in workshop/preprint positioning material
(cover letters, abstracts written for a submission portal, slide decks,
social posts) even though these exact framings do not appear in
`paper/draft_v0.md` today — they are easy phrasings to reach for under
submission-deadline pressure and each one oversteps the draft's actual
claim boundary:

- describing VeriPatch-RR as a definitive or final benchmark, rather than
  the relational evaluation instrument this project actually built and
  bounded;
- describing the label-vs-polarity finding as proof that a model internally
  relies on diff polarity, rather than the behavioral evidence (input
  interventions on outputs, no probing or activation evidence) the draft
  itself is careful to scope it as;
- describing the antisymmetric repair as having solved the side-order
  problem, rather than a structural constraint paired with an explicitly
  unresolved learned-repair objective;
- describing CrossVul results as showing better generalization, rather than
  the confound reading the draft supports — that CrossVul's higher raw
  canonical accuracy tracks a stronger presentation shortcut, not stronger
  reasoning.

## 8. Venue-Search Protocol

**This plan's own Section 3 web research is already a snapshot, not a
standing fact.** CFP deadlines shift, workshops rotate their co-located
conference (DL4C alone has moved ICLR → ICLR → ICLR → NeurIPS → ICML across
its five editions), and some editions never confirm a next-year date at
all. A future PR must re-run this search live against official pages, not
cite the venue names recorded in this document as current.

**Step 1 — start from live aggregators, not memory.** This plan located two
standing tracker sites that are the right starting point for any future
search:

- `se-deadlines.github.io` — tracks ICSE, MSR, ESEC/FSE, ASE, and their
  affiliated workshops, with community-maintained pull-request updates.
- `sec-deadlines.github.io` — the security/privacy-conference equivalent.

Cross-check whatever these surface against a direct search using the target
type terms in Section 9, since aggregators can lag a freshly-announced CFP.

**Step 2 — verify against the official CFP page, not a secondary source.**
Treat the workshop's own site or the parent conference's official
submission-system page (researchr, hotcrp, OpenReview) as the only
authoritative source. This plan's own Part 1 research found a concrete
example of why: a workshop's top-level landing page (e.g. the LLM4Sec
workshop site) did not surface deadline or page-limit information that a
dedicated CFP subpage was later needed to confirm — a search snippet or a
landing page is not sufficient evidence on its own.

**Step 3 — record every one of the following fields per candidate**, sourced
from the official CFP page and cited by URL:

| Field | Note |
| --- | --- |
| Workshop name | Full name, not just an acronym |
| Parent conference | e.g. "ICSE 2027," "ESORICS 2027" |
| Year | The specific edition being evaluated |
| Deadline (submission) | Exact date and timezone (most CFPs use AoE) |
| Notification date | When accept/reject decisions are sent |
| Page limit | Body-text limit; note separately whether appendices/references are excluded from the cap |
| Anonymity policy | Single-blind, double-blind, or non-blind |
| Preprint / dual-submission policy | Quote the CFP's exact language if available — this plan found this is frequently unstated or ambiguous with respect to preprints specifically (Section 5), so do not infer a favorable policy from silence |
| Scope fit | One sentence, referencing which Section 3 category this venue matches |
| Archival status | Are proceedings archival, or explicitly non-archival (e.g. DL4C's historical model) |
| Short papers / extended abstracts accepted | Yes/no, with the page range if yes |
| Code / artifact submission encouraged | Yes/no |

**Step 4 — flag passed deadlines explicitly rather than dropping them
silently.** A closed 2026-cycle deadline is still useful: most workshops
repeat annually within a few weeks of the prior year's date, so a passed
deadline is the best available estimate for when the next cycle's CFP will
open. Record it as "closed, next cycle expected around [estimated window],
unconfirmed" rather than omitting the venue.

**Step 5 — re-run this protocol immediately before acting, not once and
then trusted for months.** The right time to execute this protocol is
immediately before Section 11's recommended next PR is opened, and again
immediately before an actual submission is prepared — not now, and not
banked from this PR's Section 3 research, which should be treated as
illustrative type-grounding rather than a live shortlist.

## 9. Candidate Venue Shortlisting Plan

The six target types this plan was asked to define, each mapped to its
Section 3 category, with the fit rationale and mismatch risk restated
briefly and the concrete series this plan already found listed as **starting
points to re-verify, not confirmed targets**.

| Target type | Section 3 category | Why it might fit | Mismatch risk | Known series to re-verify first |
| --- | --- | --- | --- | --- |
| Security ML workshops | 3.4 | Direct application-domain match; values concrete, actionable findings like the CrossVul confound | May want a sharper practitioner "what to do differently" angle than an evaluation paper naturally provides | LLM4Sec (ESORICS-affiliated), LAST-X (NDSS-affiliated) — both closed for their 2026 cycle by the time of this plan's research except LLM4Sec, whose 2026 deadline could not be confirmed as open or closed |
| AI for code workshops | 3.2 | Tightest scope match found in this plan; low reframing cost | May expect generative/agentic evaluation rather than classification-based evaluation | LLM4Code (ICSE-affiliated), DL4C (rotates conference year to year) — both had their 2026 cycle conclude before this plan's research |
| Software engineering / program repair workshops | 3.3 | Values the shortcut-diagnosis rigor and reproducibility discipline | Real scope mismatch for a strict automated-program-repair audience expecting patch-generation systems, not evaluation | ICSE SVM (Software Vulnerability Management) — closer fit than a strict APR workshop; 2026 cycle concluded |
| LLM evaluation workshops | 3.1 | Best fit for the paper's actual methodological contribution (benchmark/evaluation-practice critique) | May ask for broader model-family coverage to argue the instrument itself generalizes | No workshop-tier instance confirmed in this plan's research; the closest match found was NeurIPS 2026's Evaluations & Datasets Track, which is a full conference track (higher bar, not a workshop) and had already closed |
| Trustworthy ML / AI safety evaluation workshops | 3.5 | Strong fit for the paper's claim-boundary discipline and "behavioral, not mechanistic" framing | A strictly mechanistic-interpretability-focused sub-audience may expect probing/activation evidence this paper does not have and should not add just to fit | SaTML (IEEE Secure and Trustworthy ML) — 2026 cycle (Munich, March 2026) concluded before this plan's research; next edition not yet confirmed |
| Empirical software engineering workshops | 3.6 | Values the dataset-artifact diagnosis and reproducibility artifacts | Real restructuring cost (explicit RQ framing, SE-style threats-to-validity) and genuine audience-fit uncertainty for an ML-behavioral-audit paper | MSR (Mining Software Repositories) — 2026 technical-track deadline already passed by the time of this plan's research |

**No final target is named here**, consistent with the instruction this
section was given: every series above either had its identifiable 2026
deadline already closed, or its deadline status could not be confirmed from
the pages this plan's research could reach. Section 8's protocol, run fresh
against official CFP pages, is the required next step before any of these
becomes an actual target — not this table.

## 10. Preprint Release Decision

Answered strictly, one question at a time:

**Should it post immediately? No.** `docs/PREPRINT_PREPARATION_PLAN.md`'s
three blockers (no external read, placeholder author metadata, no PDF build
path) are unchanged and unresolved by this plan. Posting now would also
forgo the ability to check a target venue's anonymity policy before it
matters — two of the three concrete double-blind venues found in Section 3
have submission-overlap language whose treatment of preprints specifically
is unconfirmed (Section 5).

**Should it wait until workshop targeting is done?** **Yes, at minimum.**
This is a hard prerequisite, not a preference: whether a preprint conflicts
with a specific venue's policy cannot be evaluated until a specific venue
is known, and Section 9 deliberately named no final venue. Section 8's
live search must run first.

**Should it wait until one workshop submission is prepared? Yes — this is
the actual recommended trigger.** Preparing a submission (the Section 6
compression pass, plus resolving author metadata) is not idle waiting: it
does the same content-freeze and metadata work the preprint independently
needs per `docs/PREPRINT_PREPARATION_PLAN.md`. Waiting for this milestone
costs nothing that would not have to happen anyway, and it is the point at
which a specific venue's actual anonymity/preprint policy becomes knowable
rather than hypothetical.

**Should it wait for feedback (the review decision itself)? Conditionally,
not always.** Under the Section 5 default (Option A, workshop first), yes —
hold the preprint until that venue's decision, to respect double-blind
review integrity. But this is venue-dependent: if a specific target venue's
CFP is confirmed, in writing, to tolerate a concurrent public preprint
(Section 5's condition for Option C), the preprint can post at submission
time rather than waiting for the decision. The default is "wait for the
decision"; the exception requires a confirmed, not assumed, favorable
policy.

**Recommendation: post the preprint once a workshop submission is prepared
and that submission's target venue's preprint/anonymity policy has been
explicitly checked** — timing the actual post according to that policy
(simultaneous if confirmed tolerant, after the decision if not or if
unconfirmed). This is a single coherent recommendation, not four
independent answers: the workshop-submission milestone is the gate, and the
venue's own confirmed policy — not a general ML-community assumption —
decides what happens at that gate.

## 11. Recommended Next PR

Options considered, per this plan's brief:

- A. `paper: add preprint metadata and responsible-use statement`
- B. `docs: shortlist current workshop targets`
- C. `paper: create workshop short-paper outline`
- D. `paper: create preprint PDF build path`
- E. `research: define real-world directional patch review task`

**Recommendation: B — `docs: shortlist current workshop targets`.**

Rationale:

- **B resolves the one unknown every other option depends on.** C (a
  short-paper outline) cannot be scoped precisely without knowing the
  target venue's actual page limit and which of Positioning A or
  Positioning B (Section 4) to emphasize — both are venue-specific facts B
  would establish. Writing C before B risks producing an outline tuned to
  the wrong page budget or the wrong emphasis.
- **B is time-sensitive in a way the others are not.** Section 9 found one
  live near-term window (LLM4Sec at ESORICS 2026) whose exact deadline this
  plan could not confirm, plus a second window (NeurIPS 2026 workshops)
  whose individual CFPs were not yet published as of this plan's research.
  Both require checking *now*, not after other work — a closed window
  cannot be reopened by finishing A, C, or D first.
- **A remains valid future work but is no longer the most urgent item.**
  `docs/PREPRINT_PREPARATION_PLAN.md` recommended A as its own next PR, and
  that recommendation is not wrong — but Section 10 of this plan concludes
  the preprint itself should wait until a workshop submission is prepared,
  which lowers A's relative urgency without eliminating its value (the
  author-metadata fix A performs is needed for the workshop submission too,
  just not gated on being done first).
- **D (PDF build path) is explicitly deferred by Section 10.** Building a
  submittable PDF for a preprint that Section 10 says should not post yet
  is premature.
- **E is out of scope by this plan's own brief.** A new research direction
  (real-world directional patch review) is a different line of work
  entirely; pursuing it now would also reintroduce exactly the kind of new
  experimental work this plan and `docs/PREPRINT_PREPARATION_PLAN.md` were
  both explicitly scoped to avoid.

## 12. Final Recommendation

**Primary external feedback route: workshop submission**, not preprint
posting and not cold PI outreach as the primary mechanism (Section 1) —
workshop review is the one channel that structurally guarantees an outside
reaction within a bounded time.

**Primary audience: AI for Code / Code Generation workshops** (Section 3.2
/ Positioning A), with **Security / Vulnerability Analysis workshops**
(Section 3.4 / Positioning B) pursued as a parallel near-term track given
the LLM4Sec@ESORICS window this plan could not confirm as closed
(Section 9, pending Section 8 verification) — not a fallback, a concurrent
second track.

**Should a preprint post now? No.** Post it once a workshop submission is
prepared and that venue's preprint/anonymity policy is explicitly checked
(Section 10) — timed by that policy, not by convenience.

**Should the project submit to a workshop first? Yes** — this is the
Section 5 default strategy, chosen because workshop review is the only
mechanism here that reliably supplies the real external feedback the
project owner asked for, and because the preprint is not independently
ready to post faster anyway (`docs/PREPRINT_PREPARATION_PLAN.md`).

**What must be done before contacting workshop/preprint audiences:**

1. Run Section 8's live venue search against official CFP pages (the
   recommended next PR, Section 11) — resolves which specific venue and
   confirms its deadline, page limit, and anonymity/preprint policy.
2. Resolve the author-metadata blocker (`CITATION.cff` placeholder) —
   required for any real submission regardless of venue.
3. Compress the paper per Section 6's specification into an actual
   submission once a target venue's page budget and emphasis (Positioning
   A vs. B) are confirmed by step 1.

**What should not be done next:**

- Another self-produced audit or targeting document — this plan, together
  with `docs/PREPRINT_PREPARATION_PLAN.md`, is already the second
  consecutive planning document in this line; the next artifact this
  project needs is a live venue search and, eventually, external contact,
  not a third plan.
- Any new experiment, model training, or result — unchanged from this
  plan's own scope boundary and `docs/PREPRINT_PREPARATION_PLAN.md`'s.
- Posting the preprint before a target venue's policy is checked, even
  though every mechanical preprint blocker (metadata, PDF) could
  theoretically be resolved independently of workshop targeting.
- Naming a specific venue as "the" target based on this plan's Section 3/9
  research alone — that research is explicitly a snapshot requiring live
  re-verification (Section 8), not a standing shortlist.
- Mixing in the separate real-world directional patch review research line
  — that remains a distinct, later body of work, not part of this
  targeting line.

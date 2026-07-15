# Preprint Preparation Plan

This is a planning document, not the preprint itself. It defines what remains
before the current Markdown draft (`paper/draft_v0.md`) can be posted as a
public preprint. It does not run experiments, train or tune models, change
the thesis, add new results, or add new `[RESULT: ...]` anchors. It updates
no paper claims.

It builds on, and does not duplicate, `docs/PREPRINT_READINESS_CHECKLIST.md`
(a task checkbox list scoped to paper text / figures / format / release /
external-review items). This document is the surrounding strategic plan:
it states the current readiness verdict across three distinct audiences,
the true remaining blockers, the preprint's claim boundary, the exact
artifact set, the typesetting decision, public-repo readiness, and a staged
release sequence. Where the two documents overlap, this plan defers to the
checklist for the itemized status and links to it rather than restating it.

## 1. Current Preprint-Readiness Verdict

Three different questions are conflated in casual use of "is it ready."
This plan answers them separately, because the bar rises at each stage.

| Question | Verdict | Why |
| --- | --- | --- |
| Ready as an internal working draft? | **READY** | `paper/draft_v0.md` is complete end-to-end (abstract through appendices), every `[RESULT: ...]` anchor resolves to a real report (`tests/test_paper_artifacts.py::test_paper_result_anchors_have_report_map`), and every `[RELATED: ...]` anchor resolves to `paper/references.md`. This bar has been met since before PR #67. |
| Ready for external working-draft review? | **READY** | PR #68 shipped exactly this: `docs/EXTERNAL_REVIEW_REQUEST.md`, `docs/EXTERNAL_FEEDBACK_PACKET.md`, and `docs/EXTERNAL_REVIEW_EMAIL_TEMPLATE.md` exist, are indexed in `README.md` and `reports/RESULTS_INDEX.md`, state working-draft framing, state the core claim boundary, and contain no forbidden overclaim phrases (enforced by `tests/test_external_review_packet.py`). `docs/REVIEWER_READINESS_AUDIT.md` independently verified no claim-boundary blocker exists. |
| Ready for public preprint posting? | **NOT READY** | No external human has actually read the draft yet — every readiness audit in this repository (`docs/REVIEWER_READINESS_AUDIT.md`, `docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md`, this plan) is self-produced. Posting publicly before that step spends a one-time credibility event on a draft that has not been pressure-tested by anyone outside the project. Two items in `docs/PREPRINT_READINESS_CHECKLIST.md` §1 and §6 are also still unchecked (final abstract pass, external review actually solicited and returned), and no PDF/typesetting decision has been executed (Markdown-only was *decided* but never re-verified against arXiv's actual submission requirements — see Section 6 below). |

**The difference between these three states, concretely:**

- *Internal working draft* means the document is internally consistent,
  fully cited, and every claim traces to a real artifact. This is a bar the
  author (with AI tooling) can verify alone.
- *External working-draft review* means the draft, plus a framing packet
  that states what feedback is wanted and what the work does not claim, is
  ready to hand to one qualified outside reader. This is a bar about
  packaging, not about having received that feedback yet.
- *Public preprint posting* means the draft has survived contact with at
  least one outside reader (or the project has made a deliberate, stated
  decision to post without that step), has a stable title/author/abstract
  record suitable for a permanent identifier, and has an artifact bundle
  (PDF or equivalent, figures, references) that will not need to be
  silently swapped after posting. This is a bar about the record becoming
  effectively permanent — arXiv preprints can be revised but not
  un-posted, so the cost of a mistake found post-hoc is much higher than at
  the prior two stages.

Being strict: the project has cleared the first two bars and has not yet
cleared the third. Nothing in this plan should be read as "close" collapsing
into "ready" — the gap here is a specific, actionable set of steps
(Section 3), not a vague maturity gap.

## 2. What Is Already Complete

| Item | File(s) | Status |
| --- | --- | --- |
| Title and abstract boundary | `paper/draft_v0.md` (title line 1, Abstract), `paper/abstract.md` | Complete; claim-bounded. See Section 9 for the one open wording question (not a defect). |
| Paper draft (Introduction through Discussion) | `paper/draft_v0.md` | Complete; Sections 1-10 present, no placeholder text. |
| Appendices | `paper/draft_v0.md` Appendices A-E | Complete; `docs/REVIEWER_READINESS_AUDIT.md` §5 confirms "A-E filled, no placeholders remain." |
| Main tables | `paper/tables/main_results.md`; in-draft Tables 1-4 | Complete; Table 1 (main results), Table 2 (mechanism), Table 3 (CrossVul confound), Table 4 (repair decomposition) all present with sourced numbers. |
| Mechanism/confound/repair figures | `paper/figures/figure5_label_polarity_mechanism.svg`, `figure6_crossvul_confound.svg`, `figure7_repair_decomposition.svg` | Complete (PR #64); generated deterministically from committed report JSON by `scripts/build_paper_mechanism_figures.py`, closing the figure gap `docs/REVIEWER_READINESS_AUDIT.md` had flagged. |
| Earlier endpoint/readout figures | `paper/figures/figure1_problem.svg`, `figure2_veripatch_rr.svg`, `figure3_mechanism_decomposition.svg`, `figure4_discovery_confirmation.svg` | Complete; present since before this plan's scope. |
| Result-anchor map | `paper/result_anchor_map.md` | Complete; all 14 anchors used in the draft have a map row, all referenced artifact paths exist on disk (`tests/test_paper_artifacts.py::test_paper_result_anchor_map_artifacts_exist_on_disk`). |
| References | `paper/references.md` | Complete for the working-draft bar; anchor-based (`[RELATED: ...]`), not a formatted bibliography (see Section 3). |
| Citation gaps resolved | `paper/references.md` (PR #67) | Complete; the "Citation Gaps" section that previously listed CrossVul, DeltaSecommits, PatchEval, Qwen2.5-Coder, Qwen2.5, and distilgpt2 as uncited is now empty — all six have verified entries. |
| Claim-boundary tests | `tests/test_paper_artifacts.py`, `tests/test_paper_citation_polish.py`, `tests/test_external_review_packet.py` | Complete; these tests assert anchor consistency and scan for forbidden overclaim phrases, not just format. |
| External review packet | `docs/EXTERNAL_REVIEW_REQUEST.md`, `docs/EXTERNAL_FEEDBACK_PACKET.md`, `docs/EXTERNAL_REVIEW_EMAIL_TEMPLATE.md`, `docs/EXTERNAL_PARTICIPATION_GUIDE.md` | Complete (PR #68); packaged, indexed, and claim-bounded, but not yet sent/returned as of this plan. |
| PhD/top-lab readiness audit | `docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md` | Complete (PR #66); an application-focused audit, not a preprint-readiness audit — it identifies the same "no external eyes yet" gap this plan treats as a hard blocker (Section 3). |
| Reviewer-readiness audit | `docs/REVIEWER_READINESS_AUDIT.md` | Complete; verdict "ready for external review as a working draft," no claim-boundary blocker found. |
| Release tag and metadata | `CITATION.cff`, `LICENSE` (Apache-2.0), `docs/RELEASE_CHECKLIST.md`, `docs/RELEASE_V0_1_NOTES.md` | Complete; `v0.1.0` tagged as a bounded research-artifact release, distinct from and prior to any preprint decision. |

## 3. Remaining Blockers Before Public Preprint

Most candidate items below are not true blockers. Three are:

1. **No external human has read the draft.** Every readiness verdict in this
   repository, including this one, is self-produced. `docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md`
   §1 and §11 independently reach the same conclusion: this is the single
   highest-leverage remaining step, and no other item substitutes for it.
   The external review packet (`docs/EXTERNAL_REVIEW_REQUEST.md` etc.) is
   packaged and ready to send — it has not yet been sent, or has been sent
   without a returned response as of this plan.
2. **Author identity is a placeholder.** `CITATION.cff` lists `"VeriSec Forge
   contributors"` rather than a real name. A preprint requires a real author
   of record; this cannot stay a placeholder once posted.
3. **No PDF (or arXiv-acceptable) build path exists.** The repository has a
   Markdown source of truth and SVG figures, but no script or documented
   process converts either into a submittable format. `paper/draft_v0.md`
   has never been rendered to PDF. See Section 6 for the recommended path.

Everything else is should-fix, optional, or already done:

| Item | Classification | Note |
| --- | --- | --- |
| External human review obtained | **Blocker** | See above. Packet is ready (`docs/EXTERNAL_REVIEW_REQUEST.md`); the review itself has not happened. |
| Author metadata (real name/affiliation) | **Blocker** | `CITATION.cff` line 7 says `"VeriSec Forge contributors"`; `paper/draft_v0.md` has no author line at all. |
| PDF build path | **Blocker** | No *scripts/build_paper_pdf.py* or equivalent exists; format decision (Section 6) was made but never executed. |
| Final title stability | Optional polish | `docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md` §10 states title/abstract/contributions are "already settled per commit `899ea02`." `docs/REVIEWER_READINESS_AUDIT.md` flagged one wording nuance (does "reasoning" overclaim relative to "behavioral evidence"?) as a decision, not a defect, and explicitly recommended no forced change. A final human read before the irreversible step of posting is cheap and worth doing, but this is not blocking. |
| Abstract length and clarity | Should-fix before preprint | `docs/PREPRINT_READINESS_CHECKLIST.md` §1 still lists "Final abstract pass" unchecked. The current abstract (`paper/draft_v0.md` lines 3-29) is accurate and bounded but dense (~230 words in one paragraph); a light pass for a cold arXiv reader is worthwhile. |
| Figure rendering / visual quality | Should-fix before preprint | Figures are SVG (`paper/figures/*.svg`), fine for a Markdown/HTML reading path but not guaranteed to render inside a LaTeX/Pandoc PDF pipeline without conversion. Tied to the Section 6 decision. |
| References format | Should-fix before preprint | Content-complete (10 sources, no gaps as of PR #67) but still an anchor bridge (`[RELATED: ...]` in `paper/references.md`), not a formatted bibliography. Acceptable for a Markdown-only preprint (see Section 6 Option A); would become a blocker only under a LaTeX/BibTeX conversion (Option B). |
| Bibliography completeness | Not needed | Already resolved in PR #67; `paper/references.md` states "No citation gaps remain as of this pass," verified by `tests/test_paper_citation_polish.py`. |
| License / data availability statement | Optional polish | `LICENSE` (Apache-2.0) and `CITATION.cff` exist at repo level; `paper/draft_v0.md` Appendix A substantively covers artifact/data availability. A one-line explicit "Data and Code Availability" pointer in the paper body itself (not a new claim, just a pointer) would be a nice-to-have, not a gap. |
| Reproducibility statement | Not needed | Appendix A/B/C already cover bootstrap protocol, runtime visibility schema, and pure-counting reproduction scripts in detail. |
| Limitations / ethics / responsible-use statement | Should-fix before preprint | Section 9 Limitations is thorough and claim-bounded, but there is no single explicit "responsible-use" paragraph naming deployment risk in one place (see Section 8 of this plan). Recommended as a small addition in a future PR, not this one. |
| Acknowledgments | Not needed | No advisor, funding source, or collaborator is currently claimed anywhere in the repository; adding an acknowledgments section would have nothing true to say yet. Add one only if that changes (e.g., after the external reviewer step). |
| Appendices length | Not needed | A-E are complete and scoped to what the draft's claims require; `docs/REVIEWER_READINESS_AUDIT.md` found no placeholder or bloat issue. |
| arXiv category choice | Should-fix before preprint | Not yet decided. Likely candidates given the content (secure-code ML evaluation, not a systems or theory paper): `cs.CR` (Cryptography and Security) as primary, `cs.SE` (Software Engineering) or `cs.LG` (Machine Learning) as cross-list. This is a five-minute decision at submission time, not a drafting task, but it is undecided today. |
| Anonymous vs non-anonymous version | Blocker (same root cause as author metadata) | arXiv preprints are non-anonymous by construction; this is resolved by fixing author metadata, not a separate task. |
| GitHub release / Zenodo archive | Optional polish | `v0.1.0` is already tagged (`docs/RELEASE_CHECKLIST.md`); Zenodo archival was explicitly deferred there ("not part of the v0.1.0 release action"). A DOI is nice for citability but not required to post a preprint. |
| README public-facing clarity | Should-fix before preprint | `README.md` is comprehensive but, per `docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md` §2, the repository has "produced dozens of near-duplicate audit and report documents... A reader has to work to find the three or four documents that actually matter." A reader arriving from an arXiv link has less patience than an internal contributor. See Section 7. |

Do not read the should-fix and optional rows as blocking work for *this* PR —
this plan's job is to classify them, not to resolve them here.

## 4. Preprint Scope Boundary

This section verifies the required claim boundary against the current draft
text, rather than restating it abstractly. Every "may claim" line below is
already present in `paper/draft_v0.md` in comparable language; every "must
not claim" line is already an explicit disclaimer somewhere in the draft.
This boundary is a verification, not a proposed change.

**The preprint may claim:**

| Claim | Where it already appears |
| --- | --- |
| Pointwise secure-code accuracy can hide relation-violating behavior induced by patch presentation structure | Abstract, `paper/draft_v0.md` line 14; restated in §1 Introduction |
| The candidate-identity task exposes relation-consistency failures | §3 Problem Formulation, "Task boundary: candidate-identity, not directional-patch" |
| Label-only and polarity-only interventions separate two presentation effects | §6.3, Table 2 |
| Qwen and CodeBERT show behavioral replication, not shared internal mechanism | Abstract line 21 ("cross-architecture behavioral phenomenon rather than a proven shared internal mechanism"); §6.3; §9 |
| CrossVul raw canonical accuracy is confounded by stronger polarity/gold structure | §6.4, Table 3 |
| The antisymmetric readout is a structural consistency constraint | §8, Table 4 |
| Learned fine-tuning repair remains unresolved | §8 ("left as unresolved future work"); Table 4 |

**The preprint must not claim (and does not, as of this draft):**

| Forbidden claim | Where the draft blocks it |
| --- | --- |
| Claiming secure patch reasoning is solved | Abstract: "We do not claim to solve secure patch reasoning" |
| Deployed vulnerability detection | Abstract, §9 opening: "not a deployed vulnerability scanner" |
| A universal failure claim across all models | Abstract: "that models fail universally"; §9: "not a universality claim" |
| Proof of internal mechanism | Abstract, §6.3, §9: "behavioral... not a proven shared internal mechanism" |
| A learned repair claimed as validated | §8: the draft states the fine-tuning objective does not produce a repair that is validated as transferable |
| Production-ready security tool | §9 opening: "should not be used as an automated security review system without human oversight" |
| Human replacement | Not explicitly stated as a standalone sentence in the current draft — see Section 8 of this plan for the recommendation to add this explicitly. |
| Readiness for top-conference acceptance | Not a draft claim; addressed at the meta level in `docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md`, not inside the paper itself, which is correct — the paper should not claim its own venue-readiness either way. |

One gap: "does not replace human review" is present in the *supporting docs*
(`docs/EXTERNAL_FEEDBACK_PACKET.md`: "It does not replace human security
review"; `docs/EXTERNAL_REVIEW_REQUEST.md`: same) but not as a standalone
sentence inside `paper/draft_v0.md` itself — the closest existing text is the
Appendix-adjacent "should not be used as an automated security review system
without human oversight" (§9). This is a real but small gap, addressed in
Section 8.

## 5. Preprint Artifact Checklist

The exact artifact set that should exist (or be explicitly decided as N/A)
before public posting:

| Artifact | Current Path | Current Status | Action Needed | Owner / Action Type |
| --- | --- | --- | --- | --- |
| Final Markdown source | `paper/draft_v0.md` | Complete; content-frozen pending the optional abstract pass (Section 3) | None required to post; optional light abstract edit | Human judgment call, AI can draft candidates |
| Generated PDF | *(none)* | Missing — never built | Build via the Section 6 path once chosen | Mechanical, once the path is chosen |
| Figures | `paper/figures/figure1_problem.svg` … `figure7_repair_decomposition.svg` (7 files) | Complete as SVG | Verify they render inside the chosen PDF pipeline; convert to PDF/PNG only if the pipeline requires it (Section 6) | Mechanical |
| Tables | `paper/tables/main_results.md`; in-draft Tables 1-4 | Complete | None for a Markdown-only or Pandoc path; would need reformatting only under a LaTeX rewrite | Mechanical, conditional on Section 6 |
| References | `paper/references.md` | Content-complete, anchor-format (`[RELATED: ...]`), not BibTeX | Acceptable as-is for a Markdown-only or Pandoc-built preprint; BibTeX conversion needed only under a LaTeX rewrite | Deferred to the Section 6 decision |
| Result-anchor map | `paper/result_anchor_map.md` | Complete, enforced by tests | None; internal citation-bridge artifact, stays linked from the repo rather than reproduced inside the PDF itself | None |
| Reproducibility manifest | `reproducibility/*.json` (e.g. `reproducibility/cross_model_relational_audit_manifest.json`, `reproducibility/readout_confirmatory_manifest.json`, `reproducibility/frozen_backbone_readout_control_manifest.json`) | Complete, referenced from Appendix A | None | None |
| README pointer | `README.md` | Exists; has a "For External Reviewers" section but no preprint link/identifier yet (there is nothing to link to until posting) | Add a preprint link (and DOI, if archived) after posting — this is necessarily a follow-up PR, not this one | Author, future step |
| Release tag | `v0.1.0` (`docs/RELEASE_CHECKLIST.md`) | Exists, tagged as a bounded research-artifact release | Decide whether the preprint reuses `v0.1.0` or gets its own tag (e.g. a `v0.2.0` marking the preprint-ready state) | Author decision |
| Archived artifact (Zenodo) | *(none)* | Explicitly deferred (`docs/RELEASE_CHECKLIST.md`: "Deferred: not part of the `v0.1.0` release action") | Optional; decide before or after posting — not required to post a preprint | Author decision, optional |
| External review packet | `docs/EXTERNAL_REVIEW_REQUEST.md`, `docs/EXTERNAL_FEEDBACK_PACKET.md`, `docs/EXTERNAL_REVIEW_EMAIL_TEMPLATE.md`, `docs/EXTERNAL_PARTICIPATION_GUIDE.md` | Complete, packaged, indexed | Actually use it: send to a qualified outside reader and get a response — this is Blocker #1 from Section 3 | Human outreach, not automatable |

## 6. PDF / Typesetting Plan

`docs/PREPRINT_READINESS_CHECKLIST.md` §4 already recorded a decision —
"Markdown-only" — for the paper's *authoring source of truth*. That decision
stands and is not revisited here. What that decision did not settle is how a
submittable PDF gets produced from that Markdown source, since no PDF has
ever been built (Section 3, Blocker #3). This section evaluates that
narrower question.

### Option A: Markdown-only preprint

**Pros:** already matches current repo; easy to diff; low overhead.

**Cons:** less standard for arXiv or formal sharing — arXiv submissions are
PDF-first, and a bare `.md` file is not a submittable artifact by itself.

### Option B: Convert to LaTeX

**Pros:** standard for arXiv; better citation/figure handling (native
BibTeX, native SVG-via-PDF figure inclusion, cross-referencing).

**Cons:** higher formatting overhead; risk of introducing mistakes during a
full-document rewrite/transcription — including, concretely, the risk of
silently dropping or misquoting a `[RESULT: ...]`-anchored number during
manual transcription, which would be a correctness regression this project
has otherwise guarded against with tests.

### Option C: Use Pandoc from Markdown to PDF

**Pros:** preserves current source of truth (`paper/draft_v0.md` stays
authoritative, consistent with the existing Markdown-only decision); faster
than a full LaTeX rewrite; arXiv accepts PDF-only submissions in relevant
categories, so a Pandoc-built PDF does not require also submitting LaTeX
source.

**Cons:** may need figure-format cleanup — `pdflatex` (Pandoc's default PDF
engine) does not natively embed SVG, so the 7 files under `paper/figures/`
would need a pre-conversion step (e.g. `rsvg-convert` or `cairosvg` to PDF)
before a Pandoc build; the reference list is already plain formatted prose
citations (not `\cite{}` keys), so, unlike Option B, no BibTeX conversion is
required — Pandoc can render `paper/references.md`'s existing format as a
plain References section with no citation-key rework.

**Recommendation: Option C.** It is the only option that both (a) resolves
Blocker #3 (no PDF exists) and (b) does not force the format decision in
`docs/PREPRINT_READINESS_CHECKLIST.md` §4 to be reopened. The cost is bounded
to one figure-conversion step; the references do not need rework. Option A is
ruled out because arXiv needs a PDF, not a bare Markdown file. Option B is
ruled out because it re-litigates a decision already made and introduces
transcription risk for no benefit this project needs (this is not a
camera-ready conference submission with strict LaTeX-template requirements).

**No conversion is performed in this PR.** The repository currently has no
Pandoc invocation, build script, or LaTeX toolchain for the paper (verified:
no `pandoc`, `latex`, or `.tex` references exist outside the Python virtual
environment's third-party packages). Building the actual PDF pipeline
(a *scripts/build_paper_pdf.py* or equivalent, plus the SVG pre-conversion
step) is separate, mechanical follow-up work — see Section 10, Stage 3.

## 7. Public Repository Readiness

Evaluated as: would this GitHub repository be a fair thing to link from a
public preprint today?

| Check | Finding | Verdict |
| --- | --- | --- |
| README top-level clarity | `README.md` has a "For External Reviewers" fast path (4 links) and a "Reviewer Fast Path" section, which is good, but it is followed by a ~25-entry "Reading Order" list and a ~25-row "Headline Evidence" table. A reader arriving cold from a preprint link has less context and less patience than an internal reviewer already pointed at the repo. | Should-fix: add a short "If you arrived from the preprint" pointer at the very top, ahead of the existing reviewer sections, rather than restructuring the whole README. |
| Result index | `reports/RESULTS_INDEX.md` is well-organized by category but long (100+ lines); appropriate as a secondary/reference index, not as the first thing a preprint reader sees. | Adequate as-is; not the entry point. |
| Reproducibility instructions | README "Quick Verification" gives copy-pasteable Linux/macOS and Windows commands for a focused fresh-clone smoke path, already verified working per `docs/RELEASE_CHECKLIST.md`. `REPRODUCIBILITY.md` gives the fuller local-reproduction commands. | Done for the smoke path. |
| Artifact paths | `reports/`, `paper/`, `reproducibility/` all exist, are cross-referenced, and are checked by tests (`tests/test_paper_artifacts.py`, `tests/test_reproducibility_bundle.py`). | Done. |
| License | `LICENSE` (Apache-2.0) at repo root, referenced from `README.md` "Citation and Release Metadata". | Done at the repo level. (The `CITATION.cff` author-name placeholder is tracked separately as a blocker in Section 3 — that is an identity gap, not a license gap.) |
| Data / model download assumptions | `REPRODUCIBILITY.md`'s "Quick Check" and "Evidence-Coupled Reproduction" paths explicitly assume required dataset/prediction artifacts are "already materialized locally" — there is no documented one-command path to fetch PrimeVul, CrossVul, DeltaSecommits, PatchEval, or the `Qwen/Qwen2.5-Coder-1.5B-Instruct` checkpoint from scratch. This is very likely because at least PrimeVul has its own access/redistribution terms that this repository correctly does not try to route around, but the assumption is not stated as such anywhere a first-time cloner would see it before running a command. | Should-fix before preprint: add one explicit sentence to `REPRODUCIBILITY.md` (or `README.md`) stating that full reproduction assumes the underlying datasets/checkpoints are obtained separately per their own licenses, and pointing to where each is normally sourced. This is a documentation gap, not a missing artifact. |
| Known limitations (repo-level) | Present in depth inside the paper (`paper/draft_v0.md` §9) but there is no short pointer to it from the README's top-level sections; the closest is the bottom-of-README "Claim Boundaries" section. | Optional polish: a one-line "Limitations: see paper §9" pointer near the top would help a skimming reader, but the content already exists and is linked eventually. |
| Out-of-scope untracked or private files | `git status` at the start of this plan shows three untracked paths: `application_materials/` (admissions materials, including a `.pptx` walkthrough and a recommender-outreach email draft), *docs/REAL_WORLD_USE_CASE_DEFINITION.md* (the separate, explicitly out-of-scope real-world directional patch review line), and *reports/repair_train_status_smoke.json*. None of these are committed, so none are currently part of the public repository, and none are committed by this plan. | Flag only, no action taken: before any future `git add -A` or bulk-staging commit, these three paths should be reviewed individually — `application_materials/` in particular should probably never be committed to a research-artifact repository a preprint links to, since it contains personal/admissions content (a recommender email draft, a personal profile digest) rather than research artifacts. |
| Application-oriented docs already tracked | `docs/APPLICATION_PACKET.md`, `docs/APPLICATION_FOCUS.md`, `docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md`, and related files *are* already committed and public. They are internally honest and well-bounded (no overclaims found in this plan's review of them), so there is no correctness problem. The open question is audience fit: a PI or reviewer following a preprint link to this repository would see "PhD / Top-Lab Application Readiness Audit" alongside the research artifact, which can read as slightly unusual for a research-preprint audience even though the content itself is not misleading. | **Decision: keep tracked, do not delete or hide, but recommend future separation.** A future `docs: public repo cleanup for preprint release` PR (see Section 11) should move the application-oriented docs into a clearly labeled subdirectory (e.g. `docs/application/`) and adjust `README.md` so the primary reading path a preprint reader follows leads with the research artifact (paper, results, reproducibility) and only optionally surfaces the application-focused material. This is explicitly **not** done in this PR — see the "do not delete anything... unless clearly safe" instruction this plan was given; moving files is a separate, reviewable change, not a safe default here. |

**Overall verdict for this section: the repository is close but not yet a
clean preprint-facing surface.** Nothing found here is a correctness problem
(no false claim, no broken link, no missing test) — the gaps are entirely
about what a cold reader sees first and in what order, which is a
should-fix/optional-polish tier of work, not a blocker under the Section 3
definition. Sequencing this cleanup after the external-review and author
blockers is deliberate: an outside reviewer's attention is a scarcer
resource than a repository reorganization pass, so Sections 3's real
blockers should resolve before spending effort here.

## 8. Responsible-Use and Limitation Statements

Checking the five specific elements this plan was asked to verify, against
the actual text of `paper/draft_v0.md`:

| Required element | Present in the paper body? | Where |
| --- | --- | --- |
| This is not a deployed vulnerability scanner | Yes | Abstract disclaims being a deployed detector for vulnerabilities; §9 opening ("not a deployed vulnerability scanner. The artifact should not be used as an automated security review system without human oversight") |
| This does not replace human review | **Partially.** The closest paper-body text is §9's "should not be used as an automated security review system without human oversight," which implies but does not state "does not replace human review" as its own sentence. The exact phrase exists only in the *supporting docs* (`docs/EXTERNAL_FEEDBACK_PACKET.md`, `docs/EXTERNAL_REVIEW_REQUEST.md`), not in the paper itself. | §9 (implied); supporting docs (explicit) |
| False reassurance is dangerous | **No.** This specific framing — that a false negative (missed vulnerability) or an over-confident wrong answer is worse than no answer — does not appear anywhere in `paper/draft_v0.md`. The closest adjacent idea is the abstention option (`INSUFFICIENT_CONTEXT`) described in Appendix D, but the paper never states *why* abstention matters (i.e., the false-reassurance risk it guards against). | Not present |
| Evidence-localization and abstention are important for real use | **Partially.** Evidence localization is discussed at length as a diagnostic (§9, last limitations paragraph: "Evidence localization remains diagnostic unless independently human adjudicated"), and abstention exists as a protocol option (Appendix D: `INSUFFICIENT_CONTEXT`). But neither is framed in terms of *real-use* importance — both are framed as measurement/diagnostic limitations of this study, which is accurate for what the paper claims, but does not by itself make the responsible-use case for why a real deployment would need them. | §9, Appendix D (diagnostic framing only) |
| The current task is candidate-identity, not directional patch review | **Yes, thoroughly.** §3 "Task boundary: candidate-identity, not directional-patch" is one of the most carefully argued parts of the draft; also restated in §9 and Appendix D. | §3, §9, Appendix D |

**Finding: 1 of 5 elements fully present, 3 partially present, 1 absent.**
This is not a claim-boundary problem — nothing in the paper overclaims, and
the existing Limitations section (§9) is already unusually thorough by the
standard of `docs/REVIEWER_READINESS_AUDIT.md`'s independent review. This is
a completeness gap in one specific direction: the paper explains its
scientific limitations in detail but does not consolidate them into a
reader-facing statement of *why those limitations matter for someone who
might be tempted to use this as a real review tool*.

**Recommendation: add a short, explicit responsible-use paragraph to the
paper in a future PR.** It should be a single paragraph, placed at the start
of §9 (Limitations) or as a brief new §9.0, stating plainly: this is not a
deployed scanner and does not replace human review; a false-reassurance
failure (a confident wrong answer) is more dangerous in security review than
an abstention; evidence localization and abstention are the mechanisms a
real deployment would need and are not yet validated as such here; and the
task studied is candidate-identity, not directional patch review. All five
sentences would restate existing, already-true claims from elsewhere in the
draft — this would be a consolidation, not a new claim, and would not
require a new `[RESULT: ...]` anchor.

**Not added in this PR.** The task instruction for this plan is explicit:
add such a paragraph only if it is "a tiny, clearly necessary clarification."
A five-sentence consolidating paragraph is a deliberate editorial addition
to the paper's argument structure, not a typo-scale fix, so it is correctly
scoped to its own small follow-up PR (Section 10, Stage 2) where it can be
reviewed on its own.

## 9. Preprint Title and Abstract Check

**Current title** (`paper/draft_v0.md` line 1): *"Pointwise Accuracy Is Not
Relational Consistency: Auditing Secure Patch Models Under
Presentation-Structure Transformations."*

| Dimension | Assessment |
| --- | --- |
| Title accuracy | Accurate. The title's two halves map directly onto the paper's two main moves: the pointwise-vs-relational gap (Sections 3, 5-6) and the presentation-structure mechanism (Sections 6.3-6.4, 8). No part of the title claims something the paper does not deliver. |
| Title memorability | Reasonable. The negative-claim structure ("X is not Y") is a recognizable pattern in this literature — notably, it echoes "Attention is not Explanation" [RELATED: attention-not-explanation], which this paper itself cites in `paper/references.md`. That is a fitting, not accidental-looking, resemblance given the paper's own positioning around behavioral-vs-mechanistic evidence boundaries (§2.4). |
| Risk of overclaiming | **Already resolved, and worth recording explicitly because the record is easy to misread otherwise.** `docs/REVIEWER_READINESS_AUDIT.md` (written earlier in the project's history) flagged concern over a *prior* working title using the word "Reasoning" — *"Pointwise Accuracy Is Not Relational Reasoning."* The **current** title, verified directly against `paper/draft_v0.md` line 1 in this review, already reads "Relational **Consistency**," not "Relational Reasoning." The concern that audit raised has been addressed by the title change itself, most likely as part of the title/abstract finalization `docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md` §10 references at commit `899ea02`. No further title-overclaim risk was found in this review. |
| Whether "Relational Consistency" is the right phrase | Yes. "Consistency" names exactly the measurable, behavioral property VeriPatch-RR tests (side-order equivariance, endpoint robustness, both-directions-correct) without implying the stronger, unverified claim "Reasoning" would carry (an inferential/cognitive capability claim the paper explicitly disclaims — §6.3, §9: "behavioral, not an internal-mechanistic proof"). The word choice and the claim boundary agree. |
| Whether the abstract clearly explains candidate-identity vs. directional-patch classification | Yes. The abstract's second sentence states it directly: "a candidate-identity judgment, not a directional 'does this patch fix or introduce' judgment" (`paper/draft_v0.md` line 7-8). A reader does not need to reach §3 to encounter this distinction. |
| Whether the abstract gives enough motivation for readers outside this repo | Mostly. The abstract states the applied motivation (patch review is relational; benchmarks test it pointwise), the central finding, the cross-architecture evidence, the CrossVul confound, the repair result, and the explicit non-claims — all self-contained without repository context. The one real readability cost is density: it is a single ~230-word paragraph. This is the same gap already flagged in Section 3 as "should-fix before preprint," not a new finding. |

**Recommendation: keep the current title.** No edit is needed — the specific
overclaim risk a prior audit raised does not apply to the title as it
currently reads. The abstract needs only the light density/paragraph-break
pass already scoped in Section 3 and folded into Stage 2 of Section 10, not
a content rewrite. **No title change is made in this PR** — this section
is a verification, consistent with the instruction not to change the title
here "unless it is an obvious bug," and none was found.

## 10. Preprint Release Sequence

A staged sequence from this planning PR to an actually posted preprint. Each
stage is scoped narrowly and independently reviewable; later stages should
not be started before earlier ones land, because each stage's "what not to
change" column depends on the prior stage having actually frozen what it
says it freezes.

| Stage | Recommended PR Title / Action | Scope | What Not To Change |
| --- | --- | --- | --- |
| 1. Preprint preparation plan (this PR) | `paper: prepare preprint readiness checklist` | Add `docs/PREPRINT_PREPARATION_PLAN.md` and its test; verify all referenced paths; no other files change. | No experiments, no new results, no `[RESULT: ...]` anchors, no paper claims, no PDF build. |
| 2. Metadata and responsible-use pass | `paper: add preprint metadata and responsible-use statement` | Fix `CITATION.cff`'s placeholder author field; add an author line to `paper/draft_v0.md`; add the short responsible-use paragraph scoped in Section 8; do the light abstract density pass scoped in Section 3. | No new experiments or results; no thesis change; no repo reorganization (Stage 6); no PDF build (Stage 3). |
| 3. PDF build path | `paper: create preprint PDF build path` | Implement the Section 6 Option C path: an SVG-to-PDF pre-conversion step for `paper/figures/*.svg`, plus a Pandoc build script producing a submittable PDF from `paper/draft_v0.md`. Verify all figures, tables, and references render correctly in the output. | No paper text or claim changes beyond what Stage 2 already froze; this stage is mechanical rendering only. |
| 4. Send external review packet | *(human action, not a PR)* | Actually send `docs/EXTERNAL_REVIEW_REQUEST.md` (or the email templates in `docs/EXTERNAL_REVIEW_EMAIL_TEMPLATE.md`) to at least one qualified outside reader. This is Blocker #1 from Section 3 and cannot be resolved by an automated change. | Nothing in-repo changes at this stage. |
| 5. Incorporate external review feedback | `paper: incorporate external review feedback` (title provisional; scope depends on what comes back) | Address specific, concrete concerns the reviewer raises. If the reviewer finds no issues, this stage can be a no-op and the sequence proceeds to Stage 6. | Do not add unrequested new experiments or speculatively restructure the framing beyond what the reviewer actually flagged. |
| 6. Public repo cleanup | `docs: public repo cleanup for preprint release` | Execute the Section 7 decision: move application-oriented docs into a clearly separated location (e.g. `docs/application/`), add a short "if you arrived from the preprint" pointer near the top of `README.md`, add the data/model download-assumption note to `REPRODUCIBILITY.md`. | Do not delete any file; do not change paper claims; do not touch experiment code. |
| 7. Tag and archive | `release: prepare preprint artifact bundle` | Decide and execute whether the preprint reuses `v0.1.0` or gets a new tag; write release notes referencing the preprint; optionally archive on Zenodo for a DOI (Section 3: optional, not required). | Paper claims should already be frozen by Stage 5; this stage is packaging only. |
| 8. Post the preprint | *(human action, not a PR)* | Submit the Stage 3 PDF under the arXiv category decided in Section 3 (`cs.CR` primary, `cs.SE`/`cs.LG` cross-list candidates); once posted, open a small final PR adding the live preprint link to `README.md` and `reports/RESULTS_INDEX.md`. | Nothing about the paper's content changes at this stage — this is distribution, not authorship. |

## 11. Recommended Next PR

Options considered, per this plan's brief:

- A. `paper: add preprint metadata and responsible-use statement`
- B. `paper: create preprint PDF build path`
- C. `docs: public repo cleanup for preprint release`
- D. `paper: final preprint title and abstract pass`
- E. `release: prepare preprint artifact bundle`

**Recommendation: A — `paper: add preprint metadata and responsible-use
statement`.**

Rationale:

- **A resolves one full blocker and makes progress on another, cheaply.**
  The author-metadata blocker (Section 3, Blocker #2 — `CITATION.cff`'s
  placeholder name) is fixed entirely within this PR's scope. The
  responsible-use gap (Section 8) and the abstract density item (Section 3)
  are both small, well-scoped editorial additions with no experimental risk.
- **B (PDF build path) should follow, not precede, A.** Building a PDF before
  author metadata is finalized means the first build embeds a placeholder
  author line and has to be rebuilt once A lands. Sequencing A first avoids
  that rework.
- **C (repo cleanup) is correctly sequenced later.** Section 7 already
  classified this as should-fix, not blocker, and explicitly reasoned that
  a reviewer's attention (Blocker #1) and correct author identity
  (Blocker #2) are scarcer and more urgent than repository organization.
- **D (title/abstract pass) is largely already done.** Section 9 found the
  title needs no change and the abstract needs only the same light density
  pass already folded into A's scope — a standalone PR for this alone would
  mostly restate a conclusion this plan already reached.
- **E (release artifact bundle) is a late-stage packaging step.** Tagging
  and archiving before the paper's metadata, responsible-use framing, and
  PDF exist would tag an incomplete artifact; Section 10 places it at
  Stage 7 for this reason.

Not chosen but explicitly not dismissed: **sending the external review
packet (Stage 4)** is the single highest-leverage action in this entire
plan (see Section 12), but it is a human outreach action, not a PR, so it
does not compete with A/B/C/D/E as "the next PR." It should happen in
parallel with, not after, PR A — see Section 12.

## 12. Final Verdict

**Can this be made into a preprint?** Yes. Nothing structural blocks it. The
draft is complete, every claim is anchored to a real artifact, the claim
boundaries are already stress-tested by three independent internal audits,
and the citation gaps are closed. What remains is metadata, a PDF, and one
external read — none of which requires new research.

**Is it worth making into a preprint?** Yes, conditional on not skipping the
external-review step. The value of a preprint here is largely the same value
`docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md` §1 already identified for
applications: a public, citable, timestamped record of a complete research
loop (artifact discovery, reframing, mechanism isolation, confound
measurement, honestly-reported failed repair). That value is undercut, not
gained, by posting before a single outside reader has engaged with it,
because posting is the one step in this whole sequence that is not easily
reversible — a preprint can be revised, but the "first version a stranger
found" is permanent in a way an internal draft is not.

**What is the biggest remaining blocker?** Getting one qualified person
outside this project to actually read the draft and react to it (Section 3,
Blocker #1). This is not a task that more internal engineering effort can
substitute for or accelerate — it depends on another person's time and
attention, which is exactly why every audit in this repository
(`docs/REVIEWER_READINESS_AUDIT.md`, `docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md`,
this plan) converges on the same conclusion from different angles.

**What is the highest-leverage next action?** Two things, in parallel, not
in sequence: (1) actually send the already-packaged external review request
(`docs/EXTERNAL_REVIEW_REQUEST.md` / `docs/EXTERNAL_REVIEW_EMAIL_TEMPLATE.md`)
to a real person today — this is fully prepared and has been sitting ready
since PR #68; and (2) execute PR A (Section 11) to close the author-metadata
gap and add the responsible-use paragraph, since that work is entirely
within the author's control and does not need to wait on (1). These do not
block each other, and running them in parallel is strictly better than the
Section 10 table's dependency order might suggest at a glance — the table
orders stages by what depends on what technically, not by what should
happen first in wall-clock time.

**What should not be done next?** Four things: (1) another self-produced
audit or readiness checklist — `docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md`
§9 already names this exact pattern as a risk ("the next document this
project needs is external, not self-generated"), and this plan itself is
the last of that genre this project should produce before an external
reader is actually obtained; (2) any new experiment, model training, or
result — the task boundary for this plan explicitly excludes it, and
Section 3's blockers are process and packaging gaps, not evidence gaps;
(3) posting to arXiv before Stage 4 (external review) completes, even
though every mechanical piece (PDF, metadata) could theoretically be ready
before then; and (4) rewriting the thesis, title, or claim boundaries in
response to imagined objections — Section 9 already found the title sound
and Section 4 already verified the claim boundary is intact; the correct
trigger for any further wording change is *actual* external feedback
(Stage 5), not anticipatory self-editing.

# AI-Use Disclosure (Draft Template)

This is a **draft, venue-neutral template**, prepared because AISec 2026
explicitly requires a generative-AI-use disclosure and future workshop or
preprint venues may require something similar. It is not itself a
submission-ready disclosure statement for any specific venue — each venue
tends to phrase its required disclosure differently (a dedicated section, a
cover-letter statement, a checkbox in the submission form), so this
template should be adapted to whatever format the actual target venue
requires once its CFP is confirmed, rather than pasted in verbatim.

The goal of this draft is to be honest and bounded: it neither overstates
AI involvement (to look more "handmade" than it is) nor understates it (to
avoid the disclosure requirement's purpose). It does not claim no AI tools
were used, because that would not be true of this project.

## How AI Tools Were Used, By Category

**1. Research code / experiment execution.** AI coding assistants were used
during this project's development to help write, debug, and refactor
research code (dataset processing, evaluation scripts, statistical analysis
scripts, and reproduction/report-building tooling under `scripts/` and
`src/vrf/`). Model training runs and inference themselves were executed by
that code, not generated post hoc by an AI tool describing results that
were never run. Numeric results reported in the paper trace to committed
artifacts under `reports/` and are checked by automated tests
(`tests/test_paper_artifacts.py`) that verify every `[RESULT: ...]` anchor
in the paper resolves to a real, on-disk report.

**2. Writing assistance.** AI writing/coding assistants were used to draft
and revise substantial portions of this project's documentation, planning
documents, and paper prose, including sections of `paper/draft_v0.md`
itself. This includes drafting text from author-provided direction, and
compressing or restructuring existing author-approved content (for example,
the workshop-paper compression work in
`paper/workshop_short_paper_outline.md`).

**3. Editing / planning assistance.** AI assistants were used for editorial
passes (tightening prose, checking claim-boundary consistency against
committed evidence, catching phrasing that could be read as overclaiming)
and for planning work (venue targeting, submission checklists, compression
strategy documents under `docs/`). This category is largely what produced
the `docs/PREPRINT_PREPARATION_PLAN.md`, `docs/WORKSHOP_PREPRINT_TARGETING_PLAN.md`,
`docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md`, and
`paper/workshop_short_paper_outline.md` planning documents.

**4. Human responsibility for claims, citations, and final text.** Every
empirical claim in the paper is the responsibility of the human author(s),
who reviewed and approved it against the underlying committed artifacts
before it was included; AI assistance did not introduce a claim, citation,
or number that the author did not review. Every citation in
`paper/references.md` was checked against its actual source rather than
generated from an AI tool's unverified recall (see the citation-gap
resolution documented in `paper/references.md`'s history). The final
submitted text, and responsibility for its accuracy, rests with the human
author(s), not with any AI tool used in its production.

## What This Disclosure Does Not Do

- It does not claim that no AI tools were used at any stage of this
  project — that would be false.
- It does not claim that AI tools independently designed the experiments,
  selected the thesis, or decided which results to report — those
  decisions were made by the human author(s); AI assistance operated
  within that direction.
- It does not include any confidential or private information (no internal
  tool names beyond general-purpose "AI coding/writing assistant" framing,
  no unpublished third-party data, no personal information beyond what is
  already public in this repository).

## Unresolved Items Before This Becomes a Real Submission Disclosure

- The exact wording and required disclosure format for the actual target
  venue (SaTML 2027, per `docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md`) is
  not yet published and must be checked once available — this template
  should be adapted to that format, not submitted as-is.
- If a venue requires naming the specific AI tool(s) used, that detail
  should be added at that time rather than guessed here.

---
name: scientific-paper-assistant
description: >-
  Draft, edit, and structure academic paper content in Markdown/LaTeX: claims,
  abstracts, results tables, figure captions, citations, and honest limitations.
  Use when writing or revising anything under paper/, wiring a number into a
  claim, building a results table, or bounding a contribution. Triggers: paper,
  abstract, draft, claim, results table, citation, bibtex, figure caption,
  limitations, related work, rebuttal.
---

> **Worked examples use the current, scientifically supported result.**
> Under the closed-world pair constraint the detector reaches balanced accuracy
> `0.8596` and the strongest semantics-free structural control reaches `0.8588`;
> the delta is `+0.0008` with a pair-group clustered 95% CI spanning zero, so no
> semantic advantage beyond diff structure is established. Withdrawn values appear
> only inside an explicit audit example whose requested action is to reject the
> claim. Source of truth: `docs/RESULT_STATUS_LEDGER.md`.


# Scientific Paper Assistant

Support VeriSec Forge's paper surface (`paper/`, `docs/`) with the project's
non-negotiable standard: **every claim is bounded, every number is anchored to a
report, and limitations are strong enough to survive a hostile reviewer.**

> Note: paper-*writing* is periodically paused in favor of experiments. Use this
> skill for the mechanics (tables, anchors, LaTeX, citations) whenever asked, but
> do not proactively push paper-text next steps unless the user signals they are
> back to writing.

## When to Use

- Editing `paper/draft_v0.md`, `paper/abstract.md`, `paper/outline.md`,
  `paper/main_claims.md`, or `paper/tables/*`.
- Turning an experiment result into a claim row with correct bounds.
- Writing figure captions, related-work, or a limitations/claim-boundary section.
- Managing citations (BibTeX) and cross-references.
- Preparing rebuttal / reviewer-response text.

## Instructions

### 1. Anchor before you assert
- Every quantitative claim must cite a `reports/*.md` file and appear in
  `paper/result_anchor_map.md`. If it isn't anchored, it isn't claimable.
- Copy numbers verbatim from the report (including CI and seed count). Never
  round a CI away or drop the `n=`.

### 2. Write the claim, then weaken it
- State the effect, then immediately state its boundary. This repo's house style:
  "X differs from the strongest semantics-free control by `+0.0008` BA
  (pair-group clustered 95% CI `[-0.0202, +0.0222]`), which is not
  distinguishable from zero, so this is a
  structural control, not evidence the model learned stronger reasoning."
- Prefer the existing evidence hierarchy (`docs/EVIDENCE_HIERARCHY.md`) over
  minting a new headline metric.

### 3. Build results tables consistently
- Match the format of `paper/tables/main_results.md`: `Claim | Main Result |
  Where To Read`. Right-align numeric columns. One row = one bounded claim.

### 4. Figures
- Editable SVG lives in `paper/`. Keep a text-editable source (SVG/`.py`), not
  only a raster. Captions state the takeaway AND the sample size / seeds.

### 5. Citations
- Keep a single `.bib`; cite by stable key. Do not invent references or DOIs —
  if a citation can't be verified, flag it as `TODO-cite` rather than fabricating.

### 6. LaTeX build hygiene
- If building PDF, follow `paper/pair_annotation_claim_boundary.md` conventions
  and the rendered-PDF inspection checklist (recent commits added one). Prefer a
  reproducible build (latexmk / documented toolchain) over ad-hoc runs.

## Best Practices & Guardrails

- **Do** keep claims narrower than numbers; report spread, not point estimates.
- **Do** separate "measurement", "mechanism", and "model improvement" language —
  the project treats these as distinct evidence tiers.
- **Don't** fabricate citations, numbers, or DOIs. Ever. Mark gaps `TODO`.
- **Don't** upgrade a smoke/pilot/AI-filled audit into a headline result.
- **Don't** silently change a checked-in number; if a report changed, update the
  anchor map in the same edit and note it.

## Examples

**Bounded claim row**
```markdown
| No semantic advantage beyond diff structure | detector `0.8596` vs strongest semantics-free control `0.8588`; delta `+0.0008`, clustered 95% CI `[-0.0202, +0.0222]` | `reports/PRIMEVUL_PAIR_COUPLED_CONSTRAINT_DECOMPOSITION.md` |
```

**Limitation sentence (house style)**
> Relation-consistent decoding removes measured relation violations
> (`0.3042 -> 0.0000`), but a randomized-pair control degrades to `0.4033`; this
> is a post-hoc structural control, not evidence of improved secure-patch
> reasoning.

## Dependencies / Tools

- `paper/` (drafts, tables, figures, `result_anchor_map.md`), `docs/EVIDENCE_HIERARCHY.md`
- LaTeX toolchain (latexmk/pdflatex) when producing PDF; Markdown otherwise
- BibTeX for references; SVG for editable figures
- Related skills: [[visualization-and-plotting]], [[literature-review-helper]], [[document-handling]]

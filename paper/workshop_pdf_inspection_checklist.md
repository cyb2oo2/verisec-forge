# Workshop Draft PDF Inspection Checklist

## Purpose

This defines what a human should actually look at when opening a PDF
built by `scripts/build_workshop_draft_pdf.py`
(`build/workshop_draft_v1.pdf` by default). It exists because
`paper/workshop_weasyprint_msys2_resolved_report.md` confirmed the build
path can now produce a real PDF on at least one contributor machine —
this checklist is what to do with that PDF once it exists, not a way to
build one. **This is not page-fit validation, not SaTML formatting
validation, and not a citation/bibliography style check** — see "Explicit
Non-Goals" below. It is a rough, mechanical sanity pass for the kind of
gross rendering problems this build path was built to catch, per
`paper/workshop_build_notes.md`'s "Why This Is Provisional" section.

## Prerequisites

A PDF must already exist. Build one following
`paper/workshop_build_notes.md`'s "How to Run the Build" section:

```bash
python scripts/build_workshop_draft_pdf.py
```

If this fails or produces no PDF, follow the toolchain and native-library
install steps documented there first — this checklist has nothing to
check until a PDF exists.

## Checklist

Work through these in order. Each item is a factual, mechanical check —
answer yes/no/count, not a qualitative judgment call, except where noted.

1. **Does the PDF open without error** in a standard PDF viewer? (Confirms
   the file weasyprint/pandoc wrote is not corrupt.)
2. **Record the raw page count.** This is a mechanical fact, not a
   page-fit judgment — do not compare it against SaTML 2027's page limit
   here (that limit is not yet published; see "Explicit Non-Goals"
   below and `paper/workshop_draft_v0_readiness_audit.md` Section 7 for
   the standing qualitative pre-PDF estimate this number should
   eventually be reconciled with, once a real limit exists).
3. **Are all figure placeholders present and readable as literal
   bracketed text** (e.g. `[Figure 1 here]`), matching the count in the
   script's own structural summary output? This build path does not
   render actual figures from `paper/figures/*.svg` — literal
   placeholder text is expected and correct, not a bug (see
   `paper/workshop_build_notes.md` "Current Limitations").
4. **Are all table placeholders present and readable as literal
   bracketed text** (e.g. `[Table 1 here]`), matching the structural
   summary's table count? Same expectation as figures — literal text is
   correct, not a rendering failure.
5. **Do `[RESULT: ...]` and `[RELATED: ...]` anchors appear as literal
   bracketed text** in reading order, rather than being silently dropped
   or garbled? They are not expected to render as formatted citations or
   a bibliography — that is a documented gap, not something this check
   should flag as broken.
6. **Are section headers present, numbered, and in the same order as
   `paper/workshop_draft_v1.md`?** A missing or reordered section would
   indicate a Markdown-to-HTML conversion problem, not a formatting
   nicety.
7. **Any obvious text truncation, overflow off the page edge, or
   garbled/mojibake characters** (especially around non-ASCII characters,
   em dashes, or code-formatted text)?
8. **Any obvious unrendered Markdown syntax** — stray `**`, `` ` ``,
   `#`, or similar characters that should have become formatting but
   appear as literal punctuation instead?
9. **Do code-formatted spans/blocks (if any) remain visually
   distinguishable** from surrounding prose, even without syntax
   highlighting?

## Explicit Non-Goals

This checklist does **not**, under any circumstance:

- **Claim page fit.** SaTML 2027's page limit is not yet published (see
  `paper/workshop_build_notes.md` "Why This Is Provisional"). Item 2's
  page count is a raw fact, not a fit/no-fit judgment.
- **Claim SaTML formatting compliance.** The build path produces a
  generic, single-column, unstyled rendering — no venue template, column
  layout, font, or margin has been applied, and this checklist does not
  pretend otherwise.
- **Validate citation or bibliography formatting.** `[RESULT: ...]` /
  `[RELATED: ...]` rendering as literal bracketed text (item 5) is the
  expected, already-documented state, not something this checklist
  certifies as submission-ready.
- **Substitute for the real typeset submission build**, once SaTML
  2027's actual template is published.
- **Anonymize, submit, or prepare the draft for external review.** This
  is strictly a local rendering sanity check.

## Recording Results

Record findings inline where this checklist is used (e.g. a dated report
file, or PR description), not by editing this checklist itself — this
file defines the check, it is not a log of any one run.

### First Application (informal, this PR)

Applied once against a fresh build of `paper/workshop_draft_v1.md` on
the same machine validated in
`paper/workshop_weasyprint_msys2_resolved_report.md`, as a smoke test
that this checklist is actually usable, not just theoretical prose:

| Item | Result |
| --- | --- |
| 1. Opens without error | Yes — `file build/workshop_draft_v1.pdf` reports `PDF document, version 1.7`; a valid `%PDF-1.7` header is present. |
| 2. Raw page count | 6 pages, via WeasyPrint's own `HTML(...).render()` API (`len(document.pages)`) — a mechanical fact, not a page-fit judgment. |
| 3. Figure placeholders | 3 of 3 present as literal text in the rendered HTML feeding WeasyPrint, matching the script's structural summary (`figure_placeholders: 3`). |
| 4. Table placeholders | 2 of 2 present as literal text, matching the structural summary (`table_placeholders: 2`). |
| 5. RESULT/RELATED anchors | 8 `[RESULT: ...]` and 8 `[RELATED: ...]` anchors confirmed present as literal text in the rendered HTML, in the same order as `paper/workshop_draft_v1.md`. |
| 6-9 | Not yet performed visually (requires opening the PDF in a viewer, which this task did not do beyond the mechanical checks above) — left for the next person to actually open the file. |

This first pass confirms items checkable programmatically from the
HTML/PDF structure without visual inspection; items 6-9 require someone
to actually open the rendered PDF and look at it, which remains
outstanding.

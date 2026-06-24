# Preprint Readiness Checklist

This checklist tracks what remains before turning the Markdown paper draft into
a public preprint. It is a planning document only; it does not change
experiments, claims, result numbers, benchmark artifacts, or release status.

## 1. Paper Text

- [ ] Final abstract pass.
- [ ] Tighten Introduction contribution wording.
- [ ] Normalize Related Work prose and citation metadata.
- [ ] Finalize Limitations language.
- [ ] Finalize Discussion ending.

## 2. Result and Claim Hygiene

- [ ] Confirm every `[RESULT: ...]` anchor maps to `paper/result_anchor_map.md`.
- [ ] Confirm every `[RELATED: ...]` anchor maps to `paper/references.md`.
- [ ] Confirm no readout variant is described as a promoted classifier.
- [ ] Confirm PR #12 low-canonical slots are described as stress evidence, not
  universal strong-model failure proof.
- [ ] Confirm the external smoke artifact is described as an adapter sanity
  check only.

## 3. Figures and Tables

- [ ] Finalize Figure 1-4 captions.
- [ ] Decide final figure numbering.
- [ ] Decide whether SVGs are acceptable for preprint or need PDF/PNG export.
- [ ] Convert `paper/tables/main_results.md` into final paper table format.

## 4. Format Decision

- [ ] Decide Markdown-only technical report vs LaTeX preprint.
- [ ] If LaTeX: create `paper/preprint/`.
- [ ] Convert references to BibTeX.
- [ ] Replace internal result anchors with formal citations or appendix
  references.

## 5. Artifact and Release

- [ ] Decide whether to tag a release.
- [ ] Decide whether to package an external artifact bundle.
- [ ] Confirm CI passes on `main`.
- [ ] Confirm fresh-clone instructions work.
- [ ] Confirm external adapter smoke instructions work.

## 6. External Review

- [ ] Prepare professor-facing summary email.
- [ ] Prepare a 5-minute reviewer reading path.
- [ ] Identify 2-3 target reviewers or labs.
- [ ] Ask for feedback on claim strength, not just writing.

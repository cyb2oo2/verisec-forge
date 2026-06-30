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

- [x] Confirm every `[RESULT: ...]` anchor maps to `paper/result_anchor_map.md`.
  All 8 anchors used in `paper/draft_v0.md` have a map row, and all 24
  artifact paths the map references exist on disk; no orphans either
  direction.
- [x] Confirm every `[RELATED: ...]` anchor maps to `paper/references.md`.
  All 9 keys used in the draft exist in `references.md`.
- [x] Confirm no readout variant is described as a promoted classifier.
  `paper/draft_v0.md` explicitly states "Readout variants are mechanism
  evidence, not promoted classifiers"; no contradicting "best/strongest/
  recommended readout" language found anywhere in `paper/`, `docs/`, or
  `reports/READOUT*.md`.
- [x] Confirm PR #12 low-canonical slots are described as stress evidence, not
  universal strong-model failure proof. Confirmed consistent in
  `paper/draft_v0.md` (distilgpt2/generative-judge slots called
  "low-canonical stress replication," "adds breadth, not a stronger
  headline").
- [x] Confirm the external smoke artifact is described as an adapter sanity
  check only. Confirmed in `docs/VERIPATCH_RR_EXTERNAL_ADAPTER.md`: "uses
  distilgpt2 runtime accounting only as a small adapter sanity check."

## 3. Figures and Tables

- [ ] Finalize Figure 1-4 captions.
- [ ] Decide final figure numbering.
- [ ] Decide whether SVGs are acceptable for preprint or need PDF/PNG export.
- [ ] Convert `paper/tables/main_results.md` into final paper table format.

## 4. Format Decision

- [x] Decide Markdown-only technical report vs LaTeX preprint. Decided:
  Markdown-only. `paper/draft_v0.md` stays the source of truth; the existing
  `tests/test_paper_artifacts.py` contract continues to apply.
- [ ] If LaTeX: create `paper/preprint/`. N/A — Markdown-only was chosen.
- [ ] Convert references to BibTeX. N/A — Markdown-only was chosen.
- [ ] Replace internal result anchors with formal citations or appendix
  references. Internal `[RESULT: ...]` / `[RELATED: ...]` anchors stay as the
  citation mechanism under the Markdown-only decision; revisit only if the
  format decision is later revisited.

## 5. Artifact and Release

- [x] Decide whether to tag a release. Tagged `v0.1.0`
  (`docs/RELEASE_CHECKLIST.md`, `docs/RELEASE_V0_1_BODY.md`).
- [ ] Decide whether to package an external artifact bundle.
- [x] Confirm CI passes on `main`. Verified in `docs/RELEASE_CHECKLIST.md`.
- [x] Confirm fresh-clone instructions work. Verified in
  `docs/RELEASE_CHECKLIST.md`.
- [x] Confirm external adapter smoke instructions work. Verified in
  `docs/RELEASE_CHECKLIST.md`.

## 6. External Review

- [ ] Prepare professor-facing summary email.
- [ ] Prepare a 5-minute reviewer reading path.
- [ ] Identify 2-3 target reviewers or labs.
- [ ] Ask for feedback on claim strength, not just writing.

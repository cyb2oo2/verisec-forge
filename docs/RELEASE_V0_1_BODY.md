# VeriSec Forge v0.1 — Draft Release Body

This is a draft of the text that would accompany a future `v0.1.0` GitHub
release. It is staged here for review and is not published as a release.
Creating the actual GitHub release, tag, or Zenodo DOI is a separate,
explicit action covered by [`docs/RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md).

---

## VeriSec Forge v0.1.0

VeriSec Forge v0.1 is a research artifact for studying
relation-preserving behavior in secure patch reasoning.

It packages the retained VeriPatch-RR measurement line, paper-facing reports,
external adapter path, decoder controls, and reproducibility smoke checks into
a citable artifact surface.

### What this release is

- VeriPatch-RR relational benchmark artifacts.
- Retained Qwen smoke evidence.
- Cross-model relational audits.
- Readout and mechanism controls.
- Relation-consistent decoder controls, including stress validation and
  identity-distortion failure audit.
- External adapter and reproducibility smoke path.
- Project atlas, experiment registry, reviewer checklist, and result index.

### What this release is not

- Not a deployed vulnerability scanner.
- Not a leaderboard.
- Not a model-quality benchmark release.
- Not evidence that decoding improves model reasoning.
- Not a claim that secure patch reasoning is solved.
- Not a replacement for human security review.
- Not a formal preprint or archival paper release.

### Reading order

- [README](../README.md)
- [Reviewer Checklist](REVIEWER_CHECKLIST.md)
- [Project Atlas](PROJECT_ATLAS.md)
- [Results Index](../reports/RESULTS_INDEX.md)
- [Reproducibility](../REPRODUCIBILITY.md)

### Citation

See [`CITATION.cff`](../CITATION.cff). Citation title:

```text
VeriSec Forge: Relation-Preserving Secure Patch Reasoning
```

Use this citation for the research artifact, not as a citation to a formal
paper or benchmark leaderboard.

---

## DOI Archive Notes (Zenodo)

These notes describe what an eventual Zenodo archive of this release would
need. They do not initiate archival, request a DOI, or create a Zenodo entry.

- **Archived title**: same as the `CITATION.cff` title above — do not
  introduce a separate marketing title for the archived record.
- **Version**: should match the GitHub release tag (e.g. `v0.1.0`) and the
  `version` field already set in `CITATION.cff`.
- **License**: Apache-2.0, matching [`LICENSE`](../LICENSE) and the
  `license` field in `CITATION.cff`.
- **Description**: reuse the "What this release is" / "What this release is
  not" sections above verbatim rather than re-summarizing, so the archived
  claim boundary cannot drift from the repository's own release notes.
- **Keywords**: reuse the `keywords` list already present in
  `CITATION.cff` rather than adding new ones at archive time.
- **Post-DOI step**: once a DOI is assigned, the only required follow-up is
  updating `CITATION.cff` with the DOI and `identifiers` field — no other
  release content should change as a result of archival.

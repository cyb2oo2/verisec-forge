# Release Checklist

This checklist tracks what remains before tagging VeriSec Forge v0.1 as a
public research artifact. It is release hygiene only; it does not change
experiments, claims, benchmark artifacts, outreach operations, or paper text.

## Metadata

- [x] Add `CITATION.cff`.
- [x] Add v0.1 release notes.
- [x] Link release metadata from `README.md`.
- [ ] Decide final release tag name, likely `v0.1.0`.
- [ ] Confirm repository license metadata is suitable for release.
- [ ] Decide whether to archive with Zenodo after GitHub release creation.

## Artifact Boundary

- [ ] Confirm the release notes still say this is not a deployed vulnerability
  scanner.
- [ ] Confirm the release notes still say this is not a leaderboard.
- [ ] Confirm the release notes still say this is not a model-quality benchmark
  release.
- [ ] Confirm the release notes still say this is not evidence that decoding
  improves model reasoning.
- [ ] Confirm external smoke artifacts remain framed as adapter sanity checks.

## Reproducibility

- [ ] Confirm CI passes on `main`.
- [ ] Confirm focused fresh-clone smoke instructions work.
- [ ] Confirm external adapter smoke instructions work.
- [ ] Confirm experiment registry and experiment matrix are in sync.
- [ ] Confirm retained JSON reports referenced by `reports/RESULTS_INDEX.md`
  exist.

## Release Action

- [ ] Create a GitHub release from the chosen tag.
- [ ] Attach or reference the bounded artifact surface only.
- [ ] Do not add leaderboard language to the release body.
- [ ] Do not claim the release is a formal preprint.
- [ ] If creating a DOI, confirm citation metadata after DOI assignment.

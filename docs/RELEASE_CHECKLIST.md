# Release Checklist

This checklist tracks what remains before tagging VeriSec Forge v0.1 as a
public research artifact. It is release hygiene only; it does not change
experiments, claims, benchmark artifacts, outreach operations, or paper text.

## Metadata

- [x] Add `CITATION.cff`.
- [x] Add v0.1 release notes.
- [x] Link release metadata from `README.md`.
- [x] Stage draft release body and DOI archive notes
  (`docs/RELEASE_V0_1_BODY.md`).
- [ ] Decide final release tag name, likely `v0.1.0`.
- [x] Confirm repository license metadata is suitable for release. Fixed a
  mismatch: `pyproject.toml` declared `license = "MIT"` while `LICENSE` and
  `CITATION.cff` both say Apache-2.0; `pyproject.toml` now reads
  `Apache-2.0` to match.
- [ ] Decide whether to archive with Zenodo after GitHub release creation.

## Artifact Boundary

- [x] Confirm the release notes still say this is not a deployed vulnerability
  scanner. Verified by `tests/test_release_metadata.py`.
- [x] Confirm the release notes still say this is not a leaderboard. Verified
  by `tests/test_release_metadata.py`.
- [x] Confirm the release notes still say this is not a model-quality benchmark
  release. Verified by `tests/test_release_metadata.py`.
- [x] Confirm the release notes still say this is not evidence that decoding
  improves model reasoning. Verified by `tests/test_release_metadata.py`.
- [x] Confirm external smoke artifacts remain framed as adapter sanity checks.
  See `docs/VERIPATCH_RR_EXTERNAL_ADAPTER.md` Claim Boundary section.

## Reproducibility

- [x] Confirm CI passes on `main`. Latest run on `main` (PR #33, PR #34
  merges) is green on `ubuntu-latest` and `windows-latest`.
- [x] Confirm focused fresh-clone smoke instructions work. Ran the
  `docs/CI_TESTING_STRATEGY.md` local-equivalent pytest selection plus
  `scripts/build_reproducibility_bundle.py --check-only`; all pass.
- [x] Confirm external adapter smoke instructions work. The
  `veripatch_external_smoke_manifest.json` bundle check reports `status: ok`
  for every tracked artifact.
- [x] Confirm experiment registry and experiment matrix are in sync. Every
  `reports/*.md` / `reports/*.json` path referenced from
  `docs/PROJECT_ATLAS.md` and `reports/EXPERIMENT_MATRIX.md` exists on disk.
- [x] Confirm retained JSON reports referenced by `reports/RESULTS_INDEX.md`
  exist. All 34 referenced paths verified present.

## Release Action

- [ ] Create a GitHub release from the chosen tag.
- [ ] Attach or reference the bounded artifact surface only.
- [ ] Do not add leaderboard language to the release body.
- [ ] Do not claim the release is a formal preprint.
- [ ] If creating a DOI, confirm citation metadata after DOI assignment.

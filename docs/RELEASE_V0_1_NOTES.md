# VeriSec Forge v0.1 Release Notes

## Scope

VeriSec Forge v0.1 is a research artifact for studying
relation-preserving behavior in secure patch reasoning.

It packages the retained VeriPatch-RR measurement line, paper-facing reports,
external adapter path, decoder controls, and reproducibility smoke checks into
a citable artifact surface. These notes prepare the repository for a future
v0.1 release tag; they do not create a release, DOI, leaderboard, or preprint.

## Included

- VeriPatch-RR relational benchmark artifacts.
- Retained Qwen smoke evidence.
- Cross-model relational audits.
- Readout and mechanism controls.
- Relation-consistent decoder controls, including stress validation and
  identity-distortion failure audit.
- External adapter and reproducibility smoke path.
- Project atlas, experiment registry, reviewer checklist, and result index.

## Not Included

- Not a deployed vulnerability scanner.
- Not a leaderboard.
- Not a model-quality benchmark release.
- Not evidence that decoding improves model reasoning.
- Not a claim that secure patch reasoning is solved.
- Not a replacement for human security review.
- Not a formal preprint or archival paper release.

## Citation

Citation metadata is provided in [`CITATION.cff`](../CITATION.cff).

The citation title is:

```text
VeriSec Forge: Relation-Preserving Secure Patch Reasoning
```

Use this citation for the research artifact, not as a citation to a formal
paper or benchmark leaderboard.

## Release Boundary

The v0.1 artifact is intended to be cited as a bounded research system:

```text
measurement artifacts
+ retained reports
+ external adapter smoke path
+ decoder stress controls
+ failure-case audit
```

It should not be cited as evidence that a model has improved vulnerability
detection performance or that relation-consistent decoding improves model
reasoning.

## Pre-Tag Status

Before creating a GitHub release or Zenodo DOI, complete
[`docs/RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md).

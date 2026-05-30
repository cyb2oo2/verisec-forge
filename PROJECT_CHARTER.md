# Project Charter

VeriSec Forge is maintained as a focused research artifact for secure patch reasoning. Its job is to support a clear PhD-application claim, not to preserve every historical experiment.

## Research Question

Can secure-code models be evaluated and improved under paired vulnerable/fixed patch conditions, with explicit controls for shortcut artifacts and measurable evidence failures?

## Scope Kept

- Paired vulnerable/fixed PrimeVul evaluation.
- Diff-only and pair-coupled decision layers.
- CVE/project/time-disjoint stress tests.
- DeltaSecommits and PatchEval external checks.
- Closed-world source-aware routing and its claim boundaries.
- Evidence-coupled localization and side-inversion diagnostics.
- Artifact-backed demo and manifest-backed reproducibility.

## Scope Removed

- Historical CodeXGLUE branches.
- Generic SFT/DPO/verifier sweeps.
- Old config matrices and failure-analysis dumps.
- Repeated threshold sweeps and queue variants that are summarized by retained reports.
- Generated package metadata.

## Current Success Criteria

The project is successful if a reviewer can verify these points quickly:

1. The shortcut problem is real.
2. Paired-diff reasoning is a better formulation than standalone snippet classification.
3. Pair-coupled decoding gives stable gains under split stress.
4. External/source-aware results are useful but bounded.
5. Evidence localization exposes a decision-coupled failure mode.
6. The retained artifacts are reproducible through tests and manifests.

## Primary Entry Points

- [README](README.md)
- [Application Focus](docs/APPLICATION_FOCUS.md)
- [Application Packet](docs/APPLICATION_PACKET.md)
- [Project Story](PROJECT_STORY.md)
- [Results Index](reports/RESULTS_INDEX.md)
- [Reproducibility](REPRODUCIBILITY.md)

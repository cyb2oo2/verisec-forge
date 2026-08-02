# Project Charter

> **CORRECTED — WITHDRAWN RESULTS.**
> This document previously presented PrimeVul detector results as evidence of learned
> secure-patch reasoning. That interpretation was withdrawn after adversarial
> structural-control analysis. Under the closed-world pair constraint the fine-tuned
> detector reaches balanced accuracy `0.8596`; a **semantics-free character-level diff
> structural control** reaches `0.8588` on the same evaluation population. The difference
> is `+0.0008`, with a pair-group clustered 95% CI spanning zero (`[-0.0202, +0.0222]`)
> and a non-significant group-level sign test (19 vs 18, `p=1.0`).
> **This experiment does not establish semantic secure-patch reasoning beyond diff structure.**
> Current status: [Result Status Ledger](docs/RESULT_STATUS_LEDGER.md).

## What this project actually contributes

The project demonstrated that apparently strong vulnerability-detection performance can
collapse or be reproduced by structural shortcuts under stricter paired evaluation.
Adversarial controls showed that character-level diff structure nearly matched the
fine-tuned detector, preventing an unsupported semantic-learning claim.

Concretely:

- A same-source detector scoring `0.9524` falls to `0.4961` under paired evaluation.
- A semantics-free control reading only net added-minus-removed **characters** reaches
  `0.8627` unconstrained — above the fine-tuned detector's `0.8136` — and `0.8588` under
  the pair constraint against the detector's `0.8596`.
- The detector is `0.2584` accurate on rows where that control errs, i.e. below chance:
  it follows the structural shortcut into its errors rather than correcting them.
- Two circular evaluations were identified and withdrawn: an evidence metric whose target
  was derived from the decision it was meant to validate, and a human-confirmation step
  anchored to the pipeline's own proposals.

The contribution is the identification and measurement of shortcut-driven performance,
not a successful semantic vulnerability detector.



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
- [Project Story](PROJECT_STORY.md)
- [Results Index](reports/RESULTS_INDEX.md)
- [Reproducibility](REPRODUCIBILITY.md)

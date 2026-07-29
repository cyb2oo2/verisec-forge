# VeriSec Forge: Application One-Pager

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



![PrimeVul pair-coupled significance](reports/assets/primevul_pair_coupled_significance.svg)

## One-Sentence Summary

VeriSec Forge is a shortcut-aware secure patch/diff reasoning system that diagnoses misleading vulnerability-detection scores, replaces standalone snippet classification with paired vulnerable/fixed diff reasoning, and makes the resulting audit loop reproducible through public bundle-assisted artifacts.

## Research Motivation

Standard vulnerability-detection benchmarks can reward dataset shortcuts such as project identity, code length, CVE leakage, or split artifacts. VeriSec Forge asks a stricter question: can a model reason over paired vulnerable/fixed code changes, make consistent side decisions, and expose when evidence localization or correction gates fail?

## Three Contributions

1. Shortcut-aware benchmark diagnosis.
   A same-source PrimeVul detector reaches `0.9524` accuracy, but paired stress testing shows that score is artifact-sensitive rather than a robust semantic vulnerability-detection breakthrough. Negative controls stay near chance, the current disjoint stress matrix removes eval rows overlapping training by project/CVE/commit/file hash, and a true CVE-year time split is now materialized.

2. Structural controls show the paired-diff result is not semantic.
   **No semantic advantage beyond diff structure was established.** Under the closed-world pair constraint the detector reaches balanced accuracy `0.8596`, while a semantics-free control that reads only the net added-minus-removed **character** count of the diff reaches `0.8588` on the same evaluation population. The difference is `+0.0008`, pair-group clustered 95% CI `[-0.0202, +0.0222]`, group-level sign test 19 vs 18 (`p=1.0`). Unconstrained, that same control (`0.8627`) scores *above* the detector (`0.8136`).

   Historical, withdrawn: earlier versions of this document reported a diff-only three-seed mean of `0.8287` and a pair-coupled mean of `0.8572` with a `+0.0348` delta and CI `[0.0329, 0.0368]`, as evidence of paired-diff reasoning. Those intervals came from five heavily overlapping splits of one frozen prediction set, and the comparison gave the decoder a closed-world constraint the baseline did not receive. **That interpretation is withdrawn.**

   The result now has external stress coverage rather than only PrimeVul-internal validation: project-disjoint BA `0.8225`, later-CVE time-disjoint direct-train BA `0.8835`, DeltaSecommits pair-coupled BA `0.8563`, and PatchEval adapter three-seed mean BA `0.8172`. A three-source source-routed adapter mixture improves aggregate BA from `0.8591` to `0.8664`. The learned diff-body-only router reaches `0.9063` row routing accuracy and end-to-end routed BA `0.8664`; cached multi-seed stability checks reach 50% train-pair mean BA `0.8649` with char features, `0.8630` with token features, and `0.8634` with diff-line features. The claim is explicitly bounded as closed-world source-aware expert selection: BA gain over single is `+0.0073` with CI `[0.0000, 0.0145]`, group all-correct is not reliable, and leave-one-source stress prevents open-set overclaiming.

3. Evidence audit — withdrawn as a localization result.
   Earlier versions reported side-correct top-1 `0.7610` versus side-wrong `0.0632` as evidence that localization quality tracks side correctness. **That contrast is circular**: the target was computed from the same side decision it was meant to validate, so flipping the predicted side flips the target deterministically. The limited human-confirmation exercise cannot repair it — reviewers only ever confirmed windows the pipeline had already proposed (10/10 subset, 0 outside), so the measurement cannot record a miss. Nothing here may be described as localization accuracy, localization recall, or independently human-validated evidence quality.

## Current Evidence

- Tests: run `.\.venv\Scripts\python.exe -m pytest -q`.
- PrimeVul public bundle SHA256: `6cac8dc70f9113ee9a65c4b64ae40e99dd9bc1cf786ba348ad7e8a09f0432466`.
- PrimeVul public bundle URL: `https://github.com/cyb2oo2/verisec-forge/releases/download/primevul-repro-bundle-v1/verisec_forge_primevul_repro_bundle.zip`.
- External-generalization public bundle SHA256: `90dbaaf40665494b2b1fa62781c3e09d7ec59ed3cf3611e76b9b61a27ae3465c`.
- External-generalization public bundle URL: `https://github.com/cyb2oo2/verisec-forge/releases/download/external-generalization-bundle-v10/verisec_forge_external_generalization_bundle_v10.zip`.
- Main project story: `PROJECT_STORY.md`.
- Progressive controls: `reports/PRIMEVUL_PROGRESSIVE_CONTROLS.md`.
- Final submission statistics: `reports/FINAL_SUBMISSION_STATISTICS.md`.
- Pair-coupled multi-split report: `reports/PRIMEVUL_PAIR_COUPLED_MULTISPLIT_BALANCED.md`.
- Pair-coupled significance summary: `reports/PRIMEVUL_PAIR_COUPLED_SIGNIFICANCE.md`.
- Disjoint stress evaluation: `reports/PRIMEVUL_DISJOINT_STRESS_EVAL.md`.
- Time-disjoint split manifest: `reports/PRIMEVUL_TIME_DISJOINT_PAIR_DIFF_SPLIT.md`.
- Time-disjoint transfer result: `reports/PRIMEVUL_TIME_DISJOINT_TRANSFER.md`.
- Time-disjoint direct-train result: `reports/PRIMEVUL_TIME_DISJOINT_DIRECT_TRAIN.md`.
- Time-disjoint comparison: `reports/PRIMEVUL_TIME_DISJOINT_COMPARISON.md`.
- Time-disjoint composite stress: `reports/PRIMEVUL_TIME_DISJOINT_COMPOSITE_STRESS.md`.
- DeltaSecommits pair-diff dataset: `reports/DELTASECCOMMITS_PAIR_DIFF_DATASET.md`.
- DeltaSecommits zero-shot transfer: `reports/DELTASECCOMMITS_ZERO_SHOT_PRIMEVUL_TIME_CHECKPOINT.md`.
- CVE-disjoint stress evaluation: `reports/PRIMEVUL_CVE_DISJOINT_EVAL.md`.
- AI adjudication summary: `reports/PRIMEVUL_AI_ADJUDICATION_SUMMARY.md`.
- Patch review demo: `docs/PATCH_REVIEW_DEMO.md`.
- Patch review walkthrough: `docs/PATCH_REVIEW_WALKTHROUGH.md`.
- Learned router claim boundary: `reports/LEARNED_ROUTER_CLAIM_BOUNDARY.md`.
- Learned router stability: `reports/LEARNED_CONTENT_ROUTER_STABILITY_SUMMARY.md`.
- Learned router stability figure: `reports/assets/learned_content_router_stability.svg`.
- Reproducibility guide: `REPRODUCIBILITY.md`.

## Honest Limitations

- Evidence localization still uses pseudo labels, pilot triage, and AI-filled adjudication; final evidence labels require non-AI independent adjudication.
- Safe flip gate pools remain small and should be expanded beyond top-5/top-10 candidates.
- Project/CVE/commit/file-hash disjoint stress evaluation is covered, the true time-disjoint setting now has zero-retraining transfer, direct `<=2020` training, and a project/file-hash composite stress slice. DeltaSecommits and PatchEval now provide second- and third-source validation. Cross-source threshold calibration is not the missing lever; source-routed experts help, leave-one-source stress bounds the router as closed-world, and feature ablation shows the routed-system signal survives weaker token/diff-line views. The next check is multi-seed routing stability and richer source-specialization tradeoff analysis.
- The public bundles cover the manifest-backed PrimeVul router/evidence-coupled and external-generalization/source-routing chains. The repo still does not archive every exploratory run, raw upstream dataset, or model checkpoint.

## Next Research Steps

1. Expand AI-filled evidence adjudication and side-inversion review queues to larger stratified samples while keeping them separate from human gold.
2. Add a small non-AI evidence adjudication pass for the highest-value disagreement and insufficient-context queues.
3. Turn the artifact-backed patch-review demo into a richer external-validation walkthrough over the public bundles.

## Recommended Framing

The project should be framed as shortcut-aware paired diff reasoning plus a reproducible evidence-coupled audit loop. The strongest claim is not that a single model solves vulnerability detection, but that stricter paired evaluation, negative controls, pair-coupled decoding, and explicit failure repair protocols make secure-code reasoning more trustworthy and explainable.

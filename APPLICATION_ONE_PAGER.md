# VeriSec Forge: Application One-Pager

## One-Sentence Summary

VeriSec Forge is a shortcut-aware secure patch/diff reasoning system that diagnoses misleading vulnerability-detection scores, replaces standalone snippet classification with paired vulnerable/fixed diff reasoning, and makes the resulting audit loop reproducible through public bundle-assisted artifacts.

## Research Motivation

Standard vulnerability-detection benchmarks can reward dataset shortcuts such as project identity, code length, CVE leakage, or split artifacts. VeriSec Forge asks a stricter question: can a model reason over paired vulnerable/fixed code changes, make consistent side decisions, and expose when evidence localization or correction gates fail?

## Three Contributions

1. Shortcut-aware benchmark diagnosis.
   A same-source PrimeVul detector reaches `0.9524` accuracy, but paired stress testing shows that score is artifact-sensitive rather than a robust semantic vulnerability-detection breakthrough. Negative controls stay near chance, and the first CVE-disjoint stress check removes eval rows whose CVE appears in paired-diff training metadata.

2. Paired diff reasoning plus pair-coupled decoding.
   Diff-only paired evaluation reaches `0.8158` balanced accuracy, three-seed mean `0.8287`, and no-metadata `0.8244`. Pair-coupled decoding over five pair-key split seeds improves mean balanced accuracy to `0.8572`; the strict same-split pair-minus-bucket BA delta is `+0.0348` with bootstrap 95% CI `[0.0329, 0.0368]`. On the CVE-disjoint stress subset it remains strong at `0.8491` versus diff-only `0.8168`.

3. Evidence-coupled audit loop.
   Hunk/window localization shows that evidence quality is strongly coupled to upstream side correctness: side-correct rows reach top-1 `0.7610`, while side-wrong rows fall to `0.0632`. The current audit loop includes AI-filled adjudication for `20` routed rows, precision-first safe-flip gates, a public reproduction bundle, and an artifact-backed patch review demo.

## Current Evidence

- Tests: see the latest CI/local pytest run in the repository history.
- Public bundle SHA256: `6cac8dc70f9113ee9a65c4b64ae40e99dd9bc1cf786ba348ad7e8a09f0432466`.
- Public bundle URL: `https://github.com/cyb2oo2/verisec-forge/releases/download/primevul-repro-bundle-v1/verisec_forge_primevul_repro_bundle.zip`.
- Main project story: `PROJECT_STORY.md`.
- Progressive controls: `reports/PRIMEVUL_PROGRESSIVE_CONTROLS.md`.
- Pair-coupled multi-split report: `reports/PRIMEVUL_PAIR_COUPLED_MULTISPLIT_BALANCED.md`.
- Pair-coupled significance summary: `reports/PRIMEVUL_PAIR_COUPLED_SIGNIFICANCE.md`.
- CVE-disjoint stress evaluation: `reports/PRIMEVUL_CVE_DISJOINT_EVAL.md`.
- AI adjudication summary: `reports/PRIMEVUL_AI_ADJUDICATION_SUMMARY.md`.
- Patch review demo: `docs/PATCH_REVIEW_DEMO.md`.
- Reproducibility guide: `REPRODUCIBILITY.md`.

## Honest Limitations

- Evidence localization still uses pseudo labels, pilot triage, and AI-filled adjudication; final evidence labels require non-AI independent adjudication.
- Safe flip gate pools remain small and should be expanded beyond top-5/top-10 candidates.
- CVE-disjoint stress evaluation is covered, but project/time-disjoint validation or a second paired patch dataset remains the most important next generalization check.
- The public bundle covers the manifest-backed PrimeVul router and evidence-coupled chains, not every exploratory run, raw upstream dataset, or model checkpoint.

## Next Research Steps

1. Add project/time-disjoint validation or a second paired patch dataset.
2. Expand AI-filled evidence adjudication and side-inversion review queues to larger stratified samples while keeping them separate from human gold.
3. Turn the artifact-backed patch-review demo into a richer external-validation walkthrough once harder generalization artifacts are available.
4. Convert the significance report into a figure/table suitable for the final application packet.

## Recommended Framing

The project should be framed as shortcut-aware paired diff reasoning plus a reproducible evidence-coupled audit loop. The strongest claim is not that a single model solves vulnerability detection, but that stricter paired evaluation, negative controls, pair-coupled decoding, and explicit failure repair protocols make secure-code reasoning more trustworthy and explainable.

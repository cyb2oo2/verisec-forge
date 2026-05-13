# VeriSec Forge: Application One-Pager

## One-Sentence Summary

VeriSec Forge is a shortcut-aware secure patch/diff reasoning system that diagnoses misleading vulnerability-detection scores, replaces standalone snippet classification with paired vulnerable/fixed diff reasoning, and makes the resulting audit loop reproducible through public bundle-assisted artifacts.

## Research Motivation

Standard vulnerability-detection benchmarks can reward dataset shortcuts such as project identity, code length, or split artifacts. VeriSec Forge asks a stricter question: can a model reason over paired vulnerable/fixed code changes, make consistent side decisions, and expose when evidence localization or correction gates fail?

## Main Contributions

1. Shortcut diagnosis for secure-code evaluation.
   A same-source PrimeVul detector reaches `0.9524` accuracy, but paired evaluation shows the result is artifact-sensitive rather than a robust semantic vulnerability-detection breakthrough.

2. Paired diff reasoning as a stronger task formulation.
   Diff-only paired evaluation reaches `0.8158` balanced accuracy, three-seed mean `0.8287`, and no-metadata diff evaluation remains strong at `0.8244`. Negative controls stay near chance.

3. Pair-coupled decoding for benchmark-consistent decisions.
   Five pair-key split seeds show pair-coupled decoding improves mean balanced accuracy to `0.8572`, with mean group all-correct gain of about `+0.1114`.

4. Evidence-coupled failure analysis.
   Hunk/window localization shows that evidence quality is strongly coupled to upstream side correctness: side-correct rows reach top-1 `0.7610`, while side-wrong rows fall to `0.0632`.

5. Precision-first correction protocol.
   Safe flip gates are treated as audited, stress-tested repair candidates rather than headline scores. Project-holdout checks reveal where naive consensus fails, while evidence-conditioned gating avoids introduced side errors in the current small pool.

6. Manual evidence audit loop.
   The first `42` high-signal evidence cases have a completed `codex_pilot` audit, with `6` high-quality disagreements and `14` insufficient-context cases routed into reviewer-facing adjudication queues. These are triage artifacts, not independent human gold.

7. Public bundle-assisted reproducibility.
   The manifest-backed PrimeVul router and evidence-coupled chains are reproducible from a public GitHub Release bundle with verified SHA256 and byte size.

## Current Evidence

- Tests: `164 passed`.
- Public bundle SHA256: `6cac8dc70f9113ee9a65c4b64ae40e99dd9bc1cf786ba348ad7e8a09f0432466`.
- Public bundle URL: `https://github.com/cyb2oo2/verisec-forge/releases/download/primevul-repro-bundle-v1/verisec_forge_primevul_repro_bundle.zip`.
- Main project story: `PROJECT_STORY.md`.
- Progressive controls: `reports/PRIMEVUL_PROGRESSIVE_CONTROLS.md`.
- Manual evidence audit loop: `reports/PRIMEVUL_MANUAL_EVIDENCE_AUDIT_LOOP.md`.
- Reproducibility guide: `REPRODUCIBILITY.md`.

## Honest Limitations

- Evidence localization still uses pseudo labels plus `codex_pilot` triage; final evidence labels require independent adjudication.
- Safe flip gate pools remain small and should be expanded beyond top-5/top-10 candidates.
- Project/time/CVE-disjoint generalization remains the most important next validation step.
- The public bundle covers the manifest-backed PrimeVul router and evidence-coupled chains, not every exploratory run, raw upstream dataset, or model checkpoint.

## Next Research Steps

1. Run independent adjudication on the `6` high-quality disagreement rows and wider-context review on the `14` insufficient-context rows.
2. Expand side-inversion review queues to top-20/top-50 under the existing protocol checker.
3. Add project/time/CVE-disjoint validation or a second paired patch dataset.
4. Convert the evidence-coupled audit loop into a minimal patch-review demo/API.

## Recommended Framing

The project should be framed as shortcut-aware paired diff reasoning plus a reproducible evidence-coupled audit loop. The strongest claim is not that a single model solves vulnerability detection, but that stricter paired evaluation, negative controls, pair-coupled decoding, and explicit failure repair protocols make secure-code reasoning more trustworthy and explainable.

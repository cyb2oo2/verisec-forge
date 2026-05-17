# Next Phase Roadmap

This roadmap records the reviewer-facing interpretation of the project after the paired-diff, evidence-coupled, reproducibility, and patch-review-demo work.

## Current Positioning

VeriSec Forge should be framed as:

> Trustworthy evaluation and evidence-grounded reasoning for secure patch understanding.

The strongest claim is not that the project builds a universal vulnerability scanner. The strongest claim is that standard vulnerability-detection scores can be shortcut-prone, and that paired patch/diff reasoning with negative controls, pair-coupled decoding, evidence triage, manual adjudication, and reproducible artifacts gives a more trustworthy evaluation loop.

## Claim Hierarchy

### Core Research Contributions

1. Benchmark diagnosis / shortcut expose.
   Same-source PrimeVul detection reaches `0.9524` accuracy, but paired stress testing collapses the shortcut-sensitive setting toward chance. This is the entry point: the project identifies why easy vulnerability scores can be misleading.

2. Paired diff reasoning.
   Diff-only paired evaluation reaches three-seed mean balanced accuracy `0.8287`, and no-metadata diff evaluation remains strong at `0.8244`. This is the core positive result: after removing obvious shortcuts, paired patch structure still carries learnable security signal.

3. Pair-coupled decoding.
   Five pair-key splits reach mean balanced accuracy `0.8572`, with mean group all-correct gain `+0.1114`. This is the most method-like contribution because it uses task structure rather than only changing a model, prompt, or threshold.

### Supporting Experimental Evidence

- Negative controls: metadata-only, candidate-only, and counterpart-only controls stay near chance.
- Overlap diagnostics: exact/near-duplicate rows do not explain the paired diff result.
- Calibration hygiene: bucket routing and validation-selected thresholds are useful support, but not the headline contribution.
- Evidence propagation: side-correct rows localize far better than side-wrong rows, showing that evidence quality is coupled to upstream paired decisions.
- Precision-first gates: safe flip gates are useful repair protocols, but remain small-pool diagnostics rather than deployment-grade correction systems.

### Engineering And Portfolio Artifacts

- Public bundle-assisted reproducibility for the manifest-backed PrimeVul router and evidence-coupled chains.
- Artifact-backed patch review CLI/API/UI for walkthroughs.
- Results index, project story, application one-pager, and generated figures for reviewer orientation.

These artifacts are important for credibility and communication, but they should not displace the research contribution hierarchy.

## Current Gaps

1. External generalization.
   The main line is still PrimeVul-centered. A top-tier paper needs at least one harder external validation path: broader project-disjoint sampling, time-disjoint split, CVE-disjoint split, or a second paired patch dataset.

2. Independent evidence adjudication.
   The `codex_pilot` and `codex_draft` artifacts are triage signals. The next evidence milestone is independent adjudication of the `6` high-quality disagreement rows and wider-context review of the `14` insufficient-context rows.

3. Statistical packaging.
   Pair-coupled gains already have multi-split support, but the final paper/application package should surface confidence intervals, split variance, and significance tests in one compact table.

4. Claim focus.
   The repo contains many branches: SFT, DPO, verifier, support scorer, router, evidence localization, safe flip gates, demo. Public framing should keep three levels clear: core contributions, supporting experiments, and engineering demonstration.

## Immediate Next Steps

1. Complete independent evidence adjudication.
   Fill and apply the adjudication CSV for the `6` high-quality disagreement rows. Then run wider-context review for the `14` insufficient-context rows and decide whether larger windows are required.

2. Build one external validation split.
   Prefer the smallest defensible path first: CVE-disjoint or time-disjoint paired diff evaluation if project-disjoint balanced sampling remains infeasible from the current pool.

3. Add a final statistics table.
   Consolidate three-seed diff-only, no-metadata, five-split pair-coupled, and key controls with confidence intervals or split variance.

4. Keep demo claims bounded.
   The patch review UI should be described as an artifact-backed reviewer walkthrough over reproduced PrimeVul paired examples, not as online scanning for arbitrary new code.

## Success Criteria For A Strong Submission

- The main narrative can be explained in three contributions without mentioning every experiment branch.
- External validation shows that paired diff reasoning still carries signal outside the current easy split.
- Evidence adjudication produces reviewer-confirmed labels or clearly documents ambiguity/insufficient context.
- Reproduction from the public bundle regenerates the reports and demo-required artifacts.
- The README and application materials foreground trustworthy evaluation and evidence-grounded reasoning, not raw accuracy.

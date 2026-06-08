# Next Phase Roadmap

This roadmap records the reviewer-facing interpretation of the project after the paired-diff, evidence-coupled, external-generalization, source-routing, reproducibility, and patch-review-demo work.

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

- Public bundle-assisted reproducibility for the manifest-backed PrimeVul router/evidence-coupled and external-generalization/source-routing chains.
- Artifact-backed patch review CLI/API/UI for walkthroughs.
- Results index, project story, application one-pager, application packet, and generated figures for reviewer orientation.

These artifacts are important for credibility and communication, but they should not displace the research contribution hierarchy.

## Current Gaps

1. External generalization claim boundary.
   The project now has PrimeVul time-disjoint, project/CVE/commit/file-hash stress, DeltaSecommits, and PatchEval coverage. The remaining gap is no longer "no external validation"; it is whether the source-aware routing and paired-diff claims remain stable under larger external queues, broader languages, and open-set source shift.

2. Independent evidence adjudication.
   The `codex_pilot`, `codex_draft`, and AI-filled adjudication artifacts are triage signals. The next evidence milestone is a small non-AI confirmation pass over the highest-value disagreement and insufficient-context rows.

3. Statistical packaging.
   Pair-coupled gains and learned routed-system gains now have reviewer-facing statistics, but the final paper/application package should keep confidence intervals, split variance, and significance tests in one compact table instead of scattering them across reports.

4. Claim focus.
   The pruned repo now keeps router, evidence localization, safe flip summaries, and the demo as supporting material. Public framing should keep three levels clear: core contributions, supporting experiments, and engineering demonstration.

## Immediate Next Steps

1. Run the independent 150-pair human annotation study.
   Use two blinded annotators, report vulnerable-side and context-sufficiency kappa, and adjudicate all disagreements. Keep AI-filled adjudication separate from human gold.

2. Run controlled counterfactual shortcut interventions.
   Measure invariant prediction flips under metadata, identifier, formatting, padding, side-order, and context-range changes.

3. Train the learned joint pair model.
   Begin with side-choice-only 1.5B cross-encoder LoRA, then add evidence ranking and human-supervised abstention/calibration losses.

4. Expand external validation carefully.
   Prefer one deeper follow-up over many shallow datasets: expand PatchEval/DeltaSecommits queues, add a harder open-set source split, or add a language-family stress slice.

5. Turn the demo into an external-validation walkthrough.
   Use the public bundles to show how a reviewer can restore artifacts, inspect a paired diff, view model probability, route/source decision, support/evidence window, and failure mode.

6. Keep demo claims bounded.
   The patch review UI should be described as an artifact-backed reviewer walkthrough over reproduced PrimeVul paired examples, not as online scanning for arbitrary new code.

## Success Criteria For A Strong Submission

- The main narrative can be explained in three contributions without mentioning every experiment branch.
- External validation shows that paired diff reasoning carries signal beyond PrimeVul-internal easy splits and remains bounded under harder source shift.
- Evidence adjudication produces reviewer-confirmed labels or clearly documents ambiguity/insufficient context without treating AI adjudication as human gold.
- Reproduction from the public bundle regenerates the reports and demo-required artifacts.
- The README and application materials foreground trustworthy evaluation and evidence-grounded reasoning, not raw accuracy.

# VeriSec Forge Project Story

VeriSec Forge is a shortcut-aware secure patch/diff reasoning project. Its core idea is simple: vulnerability detection scores are not trustworthy unless we separate shortcut diagnosis, paired reasoning, evidence support, failure mining, and safe correction into auditable stages.

The project should be presented as a research system, not as a single leaderboard number.

![PrimeVul progressive controls](reports/assets/primevul_progressive_controls.svg)

## One-Sentence Pitch

I built a verifiable benchmark and calibration loop for secure-code reasoning that exposes artifact-sensitive vulnerability scores, replaces standalone snippet detection with paired vulnerable/fixed diff reasoning, and audits evidence-coupled failure repair under explicit selection protocols.

## Main Research Contributions

### 1. Benchmark Diagnosis: Standard Splits Can Mislead

The starting point is a deliberately uncomfortable result: a same-source PrimeVul detector reaches very high accuracy, but paired evaluation shows that this score is artifact-sensitive.

Key evidence:

- Same-source `PrimeVul holdout2000` detector: `accuracy = 0.9524`, `recall = 0.9709`, `specificity = 0.9339`, `f1 = 0.9533`.
- On paired vulnerable/fixed evaluation, the same detector collapses to near chance, with severe safe-side failure.
- Project identity, code length, and split artifacts are strong enough to explain much of the easy split.
- Negative controls stay near chance: metadata-only `0.5022`, candidate-only `0.5078`, counterpart-only `0.5156` balanced accuracy.

Research claim:

High vulnerability-detection accuracy on standard splits can be shortcut-prone. Paired vulnerable/fixed diffs plus negative controls provide a stricter and more informative evaluation target.

Primary artifacts:

- `reports/PRIMEVUL_PROGRESSIVE_CONTROLS.md`
- `reports/PRIMEVUL_SHORTCUT_DIAGNOSTICS.md`
- `reports/PRIMEVUL_MAIN_RESULTS.md`
- `reports/TECHNICAL_REPORT.md`

### 2. Paired Diff Reasoning: A Stronger Secure-Code Formulation

The strongest current performance result is not standalone vulnerability detection. It is paired patch/diff reasoning, where the model compares vulnerable/fixed code through a diff-like representation and a pair-coupled decoding layer.

Key evidence:

- Diff-only detector on deduplicated paired eval: balanced accuracy `0.8158`.
- Three-seed diff-only mean balanced accuracy: `0.8287`, range `0.8158-0.8382`.
- Removing prompt metadata does not break the result: diff-no-metadata reaches `0.8244`.
- Pair-coupled decoding over five pair-key split seeds reaches mean balanced accuracy `0.8572`.
- Pair-coupled minus bucket-router mean balanced-accuracy delta: `+0.0348`.
- Pair-coupled mean group all-correct gain: `+0.1114`.
- Bootstrap over split seeds keeps the strict pair-minus-bucket deltas above zero: balanced-accuracy CI `[0.0329, 0.0368]`, group all-correct CI `[0.1046, 0.1199]`.
- Per-seed paired tests are consistently favorable in the multi-split report.
- A first CVE-disjoint stress check removes all eval rows whose CVE appears in paired-diff training metadata; pair-coupled balanced accuracy remains `0.8491` versus diff-only `0.8168`.
- A harder project-disjoint stress check removes all eval rows from projects seen during paired-diff training; pair-coupled balanced accuracy remains `0.8225` on `355` balanced rows.
- A true time-disjoint paired-diff split is now materialized from full paired metadata: train `<=2020` has `6000` rows, eval `>=2021` has `1562` rows, with `0` CVE-year/CVE/pair-key overlap.
- The original paired-diff checkpoint transfers strongly to the later-CVE eval split: selected-threshold balanced accuracy `0.8412`, pair-coupled balanced accuracy `0.8745`, and group all-correct `0.8555`.
- Direct training on the `<=2020` split improves the later-CVE eval result: selected-threshold balanced accuracy `0.8745`, pair-coupled balanced accuracy `0.8835`, and group all-correct `0.8765`.
- A stricter temporal composite slice removes later-CVE eval rows that overlap training by project and file hash; the remaining `218` rows are balanced (`109/109`) and pair-coupled balanced accuracy remains `0.8853`.
- A second-source DeltaSecommits C/C++ validation set is now built from `1634` paired vulnerable/secure snapshots. On the matched Delta eval split, the PrimeVul time-trained checkpoint transfers zero-shot at default balanced accuracy `0.8333`, and pair-coupled decoding improves this to `0.8486`. Delta-only adaptation reaches pair-coupled BA `0.8563`; a short/matched PrimeVul+Delta mix reaches the best calibrated Delta single-row BA `0.8670` at threshold `0.3` and PrimeVul later-CVE pair-coupled BA `0.8809`, but does not improve Delta pair-coupled BA beyond `0.8486`.
- A lightweight source-aware expert mixture now gives the clearest next direction: routing PrimeVul-time to the PrimeVul direct-train expert and DeltaSecommits to the Delta-only expert improves aggregate pair-coupled BA from `0.8714` to `0.8755`, with group all-correct rising from `0.8603` to `0.8676`.
- A third-source PatchEval split is now materialized from `1000` CVE repair tasks into `1344` vulnerable/fixed pairs across Go, JavaScript, and Python. Zero-shot matched-mixed transfer reaches pair-coupled BA `0.8086`, lower than Delta but still above the default threshold BA `0.7955`, which supports pair-coupled decoding as a reusable structure under harder cross-language shift.
- A three-source source-routed adapter mixture now uses source-specific experts for PrimeVul-time, DeltaSecommits, and PatchEval. It improves aggregate BA from `0.8591` to `0.8664` and group all-correct from `0.8482` to `0.8570`; PatchEval-specific adaptation lifts PatchEval pair-coupled BA from zero-shot `0.8086` to a three-seed mean of `0.8172`, with range `0.8030-0.8290`. This is positive but seed-sensitive, so the honest claim is stable improvement rather than a single-seed breakthrough.
- The reverse PatchEval-expert transfer check sharpens the adapter story: PatchEval-trained seed42 reaches pair-coupled BA `0.8521` on PrimeVul-time and `0.8440` on DeltaSecommits, but remains below the matched source experts (`0.8835` and `0.8563`). Source-aware adapters are therefore useful, but the safest system design is still routing to the best available source expert.
- A first non-oracle source router removes explicit source labels from routing and uses metadata-schema features instead. It exactly matches oracle source assignment on the current three-source benchmark, preserving BA `0.8664`; this is useful as a system sanity check, but it is intentionally framed as schema-based routing, not semantic source identification.
- A stricter content-router stress check shows why this distinction matters: full prompt-surface routing also reaches `1.0` routing accuracy because source cues are visible in task headers, but a diff-body-only heuristic falls to row accuracy `0.4466`. This gives the next research target: a learned router that predicts the best expert from code-diff content rather than dataset headers.
- The learned router now validates that target: a dependency-free character n-gram Naive Bayes model reaches `0.9063` row accuracy and `0.9057` pair-group accuracy on diff-body-only source routing. It is still below oracle routing, but it converts the routing story from hand-written schema/header detection into a learnable code-diff content problem.
- The learned router now has an end-to-end system check: using a complete cross-prediction matrix for observed learned routes, learned diff-body routing reaches aggregate BA `0.8664`, group all-correct `0.8548`, and orientation `0.8681`. This matches the oracle source-routed BA without matched-mixed fallback rows, while still exposing the remaining group-consistency gap to oracle routing.
- The learned routed-system gain is now statistically bounded: learned minus single matched-mixed BA is `+0.0073` with bootstrap 95% CI `[0.0000, 0.0145]` and McNemar `p=0.024461`, but group all-correct remains non-significant with CI `[-0.0015, 0.0147]`. This makes the claim reviewer-safe: useful row-level routing signal, not a broad consistency breakthrough.
- A leave-one-source-out stress test gives the router an open-set boundary: if a source is hidden during router training, routing held-out rows to the remaining experts trails the source-specific oracle by `-0.0250` BA on PrimeVul-time, `-0.0077` on DeltaSecommits, and `-0.0242` on PatchEval. This is useful because it prevents overclaiming: the current router is a closed-world source-aware adapter selector, not an unseen-source expert discovery mechanism.
- Feature ablation shows the end-to-end system is not exclusively tied to character n-gram routing. Token `1-2` features have much lower route row accuracy (`0.7106`) but still reach routed BA `0.8627`; diff-line marker features reach route row accuracy `0.7778` and routed BA `0.8649`. The conservative interpretation is that expert routing has useful redundancy across feature views, while exact source recovery and group consistency remain sensitive.
- Multi-seed pair-group subsampling now stress-tests char, token, and diff-line routers. With only 50% of train pairs per source, routed BA means are `0.8649` for char features, `0.8630` for token features, and `0.8634` for diff-line features. Per-source deltas are uneven: PrimeVul-time is slightly below or tied with the single model, DeltaSecommits improves over single under stronger views, and PatchEval gains most over single. This sharpens the source-specialization tradeoff instead of pretending routing is uniformly beneficial.
- The router claim is now consolidated into a single boundary table: closed-world BA gain is small but statistically supported, group all-correct is not reliable, feature ablation weakens the single-fingerprint concern, and leave-one-source stress keeps the claim out of open-set expert discovery territory.
- Delta-only adaptation reaches default balanced accuracy `0.8517` and pair-coupled balanced accuracy `0.8563`.
- Full PrimeVul+Delta mixed training is not a clear win on Delta eval: default balanced accuracy is `0.8532`, while pair-coupled balanced accuracy falls to `0.8456`.

Research claim:

Secure patch reasoning benefits from treating vulnerable/fixed examples as coupled decisions. Pair-coupled decoding improves both row-level accuracy and pair/group consistency.

Primary artifacts:

- `reports/PRIMEVUL_PROGRESSIVE_CONTROLS.md`
- `reports/PRIMEVUL_PAIR_COUPLED_MULTISPLIT_BALANCED.md`
- `reports/PRIMEVUL_PAIR_COUPLED_SIGNIFICANCE.md`
- `reports/PRIMEVUL_PAIR_COUPLED_ROUTER.md`
- `reports/PRIMEVUL_CVE_DISJOINT_EVAL.md`
- `reports/PRIMEVUL_DISJOINT_STRESS_EVAL.md`
- `reports/PRIMEVUL_TIME_DISJOINT_PAIR_DIFF_SPLIT.md`
- `reports/PRIMEVUL_TIME_DISJOINT_TRANSFER.md`
- `reports/PRIMEVUL_TIME_DISJOINT_DIRECT_TRAIN.md`
- `reports/PRIMEVUL_TIME_DISJOINT_COMPARISON.md`
- `reports/PRIMEVUL_TIME_DISJOINT_COMPOSITE_STRESS.md`
- `reports/DELTASECCOMMITS_PAIR_DIFF_DATASET.md`
- `reports/DELTASECCOMMITS_ZERO_SHOT_PRIMEVUL_TIME_CHECKPOINT.md`
- `reports/DELTASECCOMMITS_CROSS_SOURCE_ABLATION.md`
- `reports/LEARNED_CONTENT_ROUTER_STABILITY_SUMMARY.md`
- `reports/LEARNED_CONTENT_ROUTER_STABILITY.md`
- `reports/assets/learned_content_router_stability.svg`
- `reports/LEARNED_ROUTER_CLAIM_BOUNDARY.md`
- `reports/PRIMEVUL_MAIN_RESULTS.md`

### 3. Evidence-Coupled Audit Loop: From Pseudo-Spans To Review Queues

The evidence line is a diagnostic and next-stage research direction. It shows that explanation quality is coupled to the upstream side decision: when the paired decision chooses the wrong side, localization largely fails. The latest work turns this from a pseudo-label-only analysis into a reviewer-facing audit workflow.

Key evidence:

- Hunk+window candidate generation raises top-8 pseudo-label coverage to `0.7073`.
- Hunk+window linear scorer reaches top-1 coverage `0.6178`.
- Oracle side-aware top-1 coverage on matched rows reaches `0.7184`.
- Pair-coupled predicted-side top-1 coverage is `0.6555`.
- Side-correct rows reach top-1 `0.7610`; side-wrong rows fall to `0.0632`.
- Pair-coupled predictions still contain `190` side-wrong rows, balanced at `95` false positives and `95` false negatives.
- High-confidence side-inversion mining extracts `86` gap-`>=0.50` hard cases across `43` pair groups.
- Manual evidence audit v1 materializes `42` unique high-signal pair keys for evidence grounding.
- A completed `codex_pilot` audit over all `42` rows gives pilot/gold agreement `22` match / `20` mismatch, with `14` insufficient-context cases.
- The audit produces `6` high-quality pilot/gold disagreements as an adjudication queue and `14` insufficient-context rows as a wider-context review queue.
- A reviewer-facing adjudication workflow now exists: CSV template, apply/analyze scripts, focused high-quality packet, and non-final `codex_draft` suggestions.
- AI-filled adjudication now covers the `20` routed rows: `3` confirmed-gold, `6` corrected-side, and `11` insufficient-context; human-confirmed rows remain `0`.

Research claim:

Evidence localization is not merely a ranking problem. It is coupled to side-decision correctness, and high-confidence side inversions are a useful source of hard-negative calibration data. Pilot evidence review and AI-filled adjudications should be treated as triage until a non-AI adjudication pass confirms the final side and evidence span.

Primary artifacts:

- `reports/PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md`
- `reports/PRIMEVUL_PAIR_EVIDENCE_LOCALIZATION.md`
- `reports/PRIMEVUL_CONFIDENT_SIDE_INVERSION_SET.md`
- `docs/MANUAL_EVIDENCE_AUDIT_GUIDE.md`
- `reports/PRIMEVUL_MANUAL_EVIDENCE_AUDIT_SET.md`
- `reports/PRIMEVUL_MANUAL_EVIDENCE_PILOT_FINDINGS.md`
- `reports/PRIMEVUL_MANUAL_EVIDENCE_REVIEW_QUEUES.md`
- `reports/PRIMEVUL_MANUAL_ADJUDICATION_STATUS_DASHBOARD.md`
- `reports/PRIMEVUL_MANUAL_EVIDENCE_ADJUDICATION_WORKFLOW.md`
- `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_WORKFLOW.md`
- `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_BRIEF.md`
- `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_PACKET.md`
- `reports/PRIMEVUL_MANUAL_EVIDENCE_INSUFFICIENT_CONTEXT_BRIEF.md`
- `reports/PRIMEVUL_AI_ADJUDICATION_SUMMARY.md`

#### Precision-First Safe Flip Gates: A Cautious Repair Protocol

The safe flip gate is intentionally framed as a small, precision-first audit layer, not as a headline benchmark score. Its value is methodological: it shows how to repair high-confidence side inversions only when evidence and protocol checks agree.

Key evidence:

- Top-5 discovery strict gate repairs `10` rows and introduces `0` side errors.
- Rank-holdout strict gate accepts `2` rows and introduces `0` side errors.
- Fresh-seed strict gate accepts `9` rows and introduces `0` side errors.
- Project-holdout strict OR gate fails stress testing: precision `0.75`, introduced side errors `3`.
- Project-holdout evidence-conditioned gate restores precision `1.0`, accepts `9`, repairs `9`, and introduces `0`.
- Gate protocol audit marks only `1` report as selection-allowed and `5` reports as audit-only.

Research claim:

Correction gates should be precision-first and protocol-audited. A gate that looks safe in development can fail under project shift; evidence-conditioned consensus is safer than unconditional repeat consensus.

Primary artifacts:

- `reports/PRIMEVUL_SIDE_INVERSION_GATE_SUMMARY.md`
- `reports/PRIMEVUL_SIDE_INVERSION_PROJECT_HOLDOUT_EVIDENCE_CONDITIONED_GATE_FAILURE_ANALYSIS.md`
- `reproducibility/primevul_evidence_coupled_manifest.json`

## What To Emphasize In A PhD Application

The strongest application narrative is not "I trained a vulnerability detector." It is:

I found that standard vulnerability-detection evaluation can be misleading, built stricter paired-diff controls, developed a pair-coupled reasoning system with stable multi-split gains, and then used evidence localization and failure mining to design a safer audit loop.

Recommended contribution framing:

- Benchmark diagnosis: shortcut-aware secure-code evaluation.
- System result: paired diff reasoning plus pair-coupled decoding.
- Research loop: evidence-coupled failure analysis and precision-first repair.
- Supporting artifact: artifact-backed patch review CLI/API/UI for reviewer-facing walkthroughs.

## What Not To Overclaim

- Do not present the same-source `0.9524` result as a robust vulnerability detection breakthrough.
- Do not present pseudo-label evidence localization as human-validated evidence-span supervision.
- Do not present `codex_pilot`, `codex_draft`, or `codex_ai_adjudication_v1` annotations as independent human labels.
- Do not present safe flip gates as a large-scale deployable correction system yet.
- Do not present the patch review demo as online scanning for arbitrary new code; it is artifact-backed over reproduced PrimeVul paired examples.
- Do not claim complete archival reproducibility for every historical experiment; the public bundles currently cover the manifest-backed PrimeVul router/evidence-coupled chain and the external-generalization/source-routing chain, but not every exploratory run, checkpoint, or upstream raw dataset.

## Current Limitations

- Evidence localization still lacks independent reviewer-confirmed final adjudications, even though the pilot audit, AI-filled adjudication pass, and adjudication workflow are now complete.
- Safe flip gate pools are small and should be expanded before being treated as a mature correction benchmark.
- Project/CVE/commit/file-hash disjoint stress evaluation is now covered, the detector stack has zero-retraining transfer, direct-training, and composite project/file-hash stress results on a true time-disjoint split, DeltaSecommits gives a second-source C/C++ ablation, and PatchEval gives a third-source Go/JavaScript/Python stress test. Cross-source calibration shows that source-aware thresholds do not materially beat the best shared threshold, while source-routed experts do help. Router stability is now summarized across char, token, and diff-line views; the remaining limitation is richer cross-source specialization tradeoff analysis.
- The repository is public bundle-assisted reproducible for the manifest-backed PrimeVul router/evidence-coupled and external-generalization/source-routing chains. It is still not a complete archive of every exploratory run, checkpoint, or upstream raw dataset.

## Next Research Steps

1. Extend AI-filled adjudication from the first `20` routed rows to a larger stratified evidence/localization sample, while keeping it separate from human gold.
2. Expand the side-inversion review queue from top-5 to top-20/top-50 under the same protocol audit.
3. Add a small non-AI evidence adjudication pass for the highest-value disagreement and insufficient-context queues.

For the reviewer-facing contribution hierarchy and next-phase success criteria, see `docs/NEXT_PHASE_ROADMAP.md`.

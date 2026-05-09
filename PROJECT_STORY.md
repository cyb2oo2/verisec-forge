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
- Per-seed paired tests are consistently favorable in the multi-split report.

Research claim:

Secure patch reasoning benefits from treating vulnerable/fixed examples as coupled decisions. Pair-coupled decoding improves both row-level accuracy and pair/group consistency.

Primary artifacts:

- `reports/PRIMEVUL_PROGRESSIVE_CONTROLS.md`
- `reports/PRIMEVUL_PAIR_COUPLED_MULTISPLIT_BALANCED.md`
- `reports/PRIMEVUL_PAIR_COUPLED_ROUTER.md`
- `reports/PRIMEVUL_MAIN_RESULTS.md`

### 3. Evidence-Coupled Audit Loop: Failure Repair Must Be Safe

The evidence line is a diagnostic and next-stage research direction. It shows that explanation quality is coupled to the upstream side decision: when the paired decision chooses the wrong side, localization largely fails.

Key evidence:

- Hunk+window candidate generation raises top-8 pseudo-label coverage to `0.7073`.
- Hunk+window linear scorer reaches top-1 coverage `0.6178`.
- Oracle side-aware top-1 coverage on matched rows reaches `0.7184`.
- Pair-coupled predicted-side top-1 coverage is `0.6555`.
- Side-correct rows reach top-1 `0.7610`; side-wrong rows fall to `0.0632`.
- Pair-coupled predictions still contain `190` side-wrong rows, balanced at `95` false positives and `95` false negatives.
- High-confidence side-inversion mining extracts `86` gap-`>=0.50` hard cases across `43` pair groups.

Research claim:

Evidence localization is not merely a ranking problem. It is coupled to side-decision correctness, and high-confidence side inversions are a useful source of hard-negative calibration data.

Primary artifacts:

- `reports/PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md`
- `reports/PRIMEVUL_PAIR_EVIDENCE_LOCALIZATION.md`
- `reports/PRIMEVUL_CONFIDENT_SIDE_INVERSION_SET.md`

### 4. Precision-First Safe Flip Gates: A Cautious Repair Protocol

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

The strongest application narrative is not “I trained a vulnerability detector.” It is:

I found that standard vulnerability-detection evaluation can be misleading, built stricter paired-diff controls, developed a pair-coupled reasoning system with stable multi-split gains, and then used evidence localization and failure mining to design a safer audit loop.

Recommended contribution framing:

- Benchmark diagnosis: shortcut-aware secure-code evaluation.
- System result: paired diff reasoning plus pair-coupled decoding.
- Research loop: evidence-coupled failure analysis and precision-first repair.

## What Not To Overclaim

- Do not present the same-source `0.9524` result as a robust vulnerability detection breakthrough.
- Do not present pseudo-label evidence localization as human-validated evidence-span supervision.
- Do not present safe flip gates as a large-scale deployable correction system yet.
- Do not claim fresh-clone full artifact reproducibility until the local artifact bundle is published through a stable external host or download pipeline.

## Current Limitations

- Evidence localization still relies on pseudo labels rather than manually verified evidence spans.
- Safe flip gate pools are small and should be expanded before being treated as a mature correction benchmark.
- Project/time/CVE-disjoint external validation remains the most important next generalization check.
- The repository is manifest-backed and has a local artifact-bundle workflow for key evidence-coupled runs, but the bundle still needs public hosting for complete fresh-clone reproduction.

## Next Research Steps

1. Add a small manual evidence-span audit set, ideally `50-200` examples, to validate pseudo-localization.
2. Expand the side-inversion review queue from top-5 to top-20/top-50 under the same protocol audit.
3. Add a protocol violation checker so stress/audit-only reports cannot accidentally become selection-allowed.
4. Publish the reproducibility artifact bundle and add a scripted download path for reviewers.

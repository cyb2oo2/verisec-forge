---
name: code-review-scientific
description: >-
  Review research code for scientific rigor, statistical correctness,
  reproducibility, claim hygiene, and project conventions. Use when reviewing
  a PR, auditing an analysis script, checking a metrics change, or validating
  that a result can honestly support a claim. Triggers: code review, PR review,
  scientific review, statistics, significance, McNemar, bootstrap, CI, seed,
  leakage, confound, claim boundary, rigor.
---

# Code Review (Scientific)

Review VeriSec Forge changes as a **scientific artifact**, not only as software.
A green unit test is necessary but not sufficient: numbers must be honest, seeds
and splits must be explicit, confounds must stay controlled, and claims must
remain narrower than the evidence.

## When to Use

- Reviewing a pull request that touches `src/vrf/`, `scripts/`, `tests/`,
  `reports/`, `paper/`, `configs/`, or `reproducibility/`.
- Auditing a new metric, significance test, ablation, or control.
- Checking whether a run is ready to promote into `reports/` / the registry.
- Answering "is this result claimable?" after a code change.

## Instructions

### 1. Scope the change against the extension rule
- Does the PR strengthen (1) paired-diff evaluation / pair-coupled decoding,
  (2) bounded external / source-routing generalization, or (3) evidence-coupled
  audit? If not, it belongs on a scratch branch — flag scope expansion.
- Prefer small, focused diffs that match neighboring style.

### 2. Correctness of the scientific object
- **Seeds:** any promoted mean uses ≥3 seeds; seeds are recorded in artifacts.
- **Splits:** the claimed disjointness axis (CVE / project / time / held-out) is
  actually enforced; no leakage of identifiers across the boundary.
- **Metrics:** use the project's metrics (`src/vrf/` evaluation helpers). Do not
  invent a new headline metric when an existing evidence-hierarchy number answers
  the question.
- **Controls:** positive results must appear next to the relevant negative
  control (metadata-only / candidate-only / counterpart-only / randomized-pair /
  polarity flip as appropriate). A lone point estimate is incomplete.

### 3. Statistics hygiene
- Prefer **paired** tests on the same rows (McNemar, bootstrap over pairs/splits)
  when comparing systems on the same evaluation set.
- Report **effect size + uncertainty** (mean delta, 95% CI, `n=`, seed count),
  not only a p-value. Multiple comparisons need correction or pre-registration
  (this repo uses fixed rules such as `|canonical delta| <= 0.02`).
- Do not claim significance from a single seed or a smoke artifact.

### 4. Reproducibility surface
- Outputs are JSON/JSONL with resolved config + git commit at the top.
- New releasable artifacts get a SHA256 entry under `reproducibility/` and a
  green `--check-only` path.
- No large checkpoints, secrets, or gitignored dumps committed.
- Vulnerability samples remain **text for measurement**, never executed.

### 5. Claim and paper hygiene
- Any number that will enter `paper/` must already live in a `reports/*.md` file
  and (when paper-facing) in `paper/result_anchor_map.md`.
- Smoke / pilot / AI-filled audit evidence must **not** be promoted into
  model-quality claims (`docs/CI_TESTING_STRATEGY.md`,
  `docs/EVIDENCE_HIERARCHY.md`).
- Boundaries are stated in prose ("structural control, not stronger reasoning").

### 6. Software quality (still required)
- Types explicit; `from __future__ import annotations` preferred.
- Logic in `src/vrf/`; scripts thin.
- Tests updated when retained library behavior or smoke contracts change.
- Path handling works on Windows and Linux (CI matrix runs both).

### 7. Write the review as findings, not vibes
- Structure: **Blocking / Non-blocking / Questions / Praise**.
- Each finding: location, why it matters scientifically, suggested fix.
- Use `references/review-rubric.md` as a scorecard for larger PRs.

## Best Practices & Guardrails

- **Do** ask "what would falsify this claim?" and check that control exists.
- **Do** verify numbers against the linked report when a PR edits paper text.
- **Do** distinguish measurement vs. mechanism vs. model-improvement language.
- **Don't** approve a PR that upgrades a smoke number into a headline claim.
- **Don't** waive hash mismatches or silent seed changes.
- **Don't** treat GPU nondeterminism as "close enough" without a documented
  tolerance and a registered seed set.

## Examples

**Blocking finding (claim inflation)**
```text
[Blocking] scripts/analyze_foo.py reports BA=0.91 on the 30-pair external
smoke and the PR's paper sentence calls it "strong open-set generalization."
The smoke is an adapter sanity check (docs/CI_TESTING_STRATEGY.md), not a
quality benchmark. Bound the claim or move the number out of paper/.
```

**Non-blocking finding (statistics)**
```text
[Non-blocking] The ablation compares systems with a two-sample t-test on
row-level accuracies. Prefer a paired bootstrap over the same pair IDs (as in
reports/PRIMEVUL_PAIR_COUPLED_SIGNIFICANCE.md) and report a 95% CI on the delta.
```

**Praise that reinforces house style**
```text
[Praise] Negative controls stay in the same table as the positive result, and
the claim sentence already carries the "not open-set expert discovery" bound.
```

## Dependencies / Tools

- Project maps: `docs/EVIDENCE_HIERARCHY.md`,
  `docs/CI_TESTING_STRATEGY.md`, `docs/REVIEWER_CHECKLIST.md`
- Anchors: `experiments/registry.json`, `paper/result_anchor_map.md`, `reports/`
- Tests: focused smoke path in `ci.yml` / README
- Rubric: `references/review-rubric.md`
- Related skills: [[research-experiment-manager]], [[reproducibility-check]],
  [[scientific-paper-assistant]], [[github-workflow-automation]]

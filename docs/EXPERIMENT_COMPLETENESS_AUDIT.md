# Experiment Completeness Audit

Organizes the project by **claim**, not chronology, and asks a blunt question
per claim: is the current evidence enough to survive a skeptical reviewer, or
is there a specific, nameable gap? This is an audit and planning document, not
a paper draft. It does not rewrite any narrative, does not present unfinished
work as evidence, and does not by itself authorize new training.

Every "current evidence" line below was checked against the committed
report/doc it cites as part of writing this audit, not recalled from memory.

## A. Relational evaluation contribution

**Claim.** Pointwise secure-code accuracy can hide relation-violating behavior
induced by patch presentation structure.

**Current evidence.**
- `reports/RELATIONAL_BENCHMARK_V2.md` — VeriPatch-RR v0.1: canonical + side-swap
  + suffix + context-pressure tiers, tokenizer-neutral, pair-cluster bootstrap.
- `reports/QWEN_SIDE_SWAP_POSITIONAL_INDEPENDENCE.md`,
  `QWEN_LABEL_ONLY_SWAP_VS_STRUCTURAL_SWAP.md`,
  `QWEN_POLARITY_ONLY_SWAP_VS_STRUCTURAL_SWAP.md` — the label-only/polarity-only
  mechanism chain.
- `src/vrf/relational_evaluation.py` — `relation_violation_rate` +
  `marginal_conditioned_violation_baseline`, the locked relational metric.
- `docs/TASK_FORMULATION.md` — candidate-identity vs. directional-patch
  boundary; confirmed by grep that no other report frames the task
  directionally ("does this patch fix or introduce") outside this doc's own
  explicit exclusion in `QWEN_POLARITY_ONLY_SWAP_VS_STRUCTURAL_SWAP.md`.
- `reports/POLARITY_GOLD_CONFOUND.md` — measures that rendering orientation is
  de-confounded from gold and that net-polarity is a spurious-but-predictive
  feature, on PrimeVul/DeltaSecommits/PatchEval.

**Current weakness.**
- The full label-only/polarity-only 2×2 has run on exactly **one architecture**
  (the Qwen decoder classifier). A separate, competency-matched CodeBERT
  checkpoint exists (`checkpoints/cls_secure_code_primevul_joint_side_choice_codebert_v1`,
  canonical accuracy 67.67% vs. Qwen's 65.50% — verified in
  `reports/CROSS_MODEL_RELATIONAL_AUDIT.md`) and has been run on the
  side-swap/endpoint mechanism, but **never** on the label-only vs.
  polarity-only decomposition specifically. The polarity-is-the-driver claim is
  therefore single-architecture.
- Transformation-family coverage is broad (label swap, polarity swap, side
  swap, terminal-phrase/endpoint padding, context window, split view, two
  diff algorithms, whitespace/comment) but no report stratifies
  polarity-sensitivity **by diff size** (small vs. large diff_bucket); it is
  implicitly covered by sampling balance, not explicitly analyzed.
- Runtime/truncation accounting is consistently maintained (every recent
  builder reports `transformation_introduced_critical_truncation_rows: 0`
  explicitly per condition) — this is in good shape, not a live gap.

**Likely reviewer attack.** *"Your entire polarity mechanism is one decoder
classifier's idiosyncrasy — show me it isn't specific to Qwen's tokenizer,
positional encoding, or training recipe."*

**Required next experiment or control.** Rerun the label-only/polarity-only 2×2
on the existing CodeBERT checkpoint (no new training needed — reuse
`scripts/predict_encoder_relational_audit.py` against newly built
label/polarity audit rows, materialized at CodeBERT's max length via the
existing `materialize_relational_runtime.py`, matching
`secure_code_cross_model_relational_audit_codebert_v1_runtime512_summary.json`'s
established pattern).

**Priority.** Must-run before serious paper draft.

**Decision.** Scope this as the next substantial experiment PR (see
"Recommendation" below), after the smaller CrossVul confound analysis.

## B. Mechanism claim

**Claim.** The side-order failure is driven by diff hunk polarity / structural
removed-added representation, not merely by prose Side A/Side B labels.

**Current evidence.** The full causal chain, verified present and internally
consistent:
- `#46` (`QWEN_SIDE_SWAP_TERMINAL_PHRASE_INTERACTION.md`) — endpoint-collapse
  fix and side-swap equivariance are separable (~14x smaller effect).
- `#47` (`QWEN_SIDE_SWAP_POSITIONAL_INDEPENDENCE.md`) — canonical vs. side-swap
  predictions are statistically independent (`phi=-0.024, p=0.56`).
- `#48` (`QWEN_LABEL_ONLY_SWAP_VS_STRUCTURAL_SWAP.md`) — relabeling alone
  (polarity fixed) leaves predictions almost unchanged (`phi=+0.914`).
- `#49` (`QWEN_POLARITY_ONLY_SWAP_VS_STRUCTURAL_SWAP.md`) — polarity flip alone
  (labels/gold fixed) collapses predictions to near-independence
  (`phi=-0.094`), completing the isolation.

**Current weakness.**
- This is a **behavioral** mechanism claim (controlled input interventions,
  deterministic model predictions), correctly *not* phrased as an internal
  "binding" claim anywhere checked — but there is genuinely **no
  activation/probing evidence**. The claim rests entirely on input-output
  behavior under controlled edits, which is real interventional evidence but
  cannot say *where* in the model polarity sensitivity lives.
- One checkpoint, one context length (1024), 600 pairs throughout the whole
  chain — explicitly acknowledged in every report's own claim boundary, not a
  hidden gap.
- `docs/EVIDENCE_HIERARCHY.md`'s own T1/T3 split already captures this
  precisely (T1 for isolation quality, T3 for generality) — the tiering itself
  is not the gap; the missing generality evidence is.

**Likely reviewer attack.** *"You've shown a correlational/interventional
signature at the input-output level. Without probing or attention analysis,
you cannot claim to understand the mechanism — only its behavioral
fingerprint."* This attack is largely pre-empted by the existing careful
phrasing (behavioral, not internal-binding), but a skeptical reviewer will
still ask for probing if the paper leans on "mechanism" language at all.

**Required next experiment or control.** Either (a) add a lightweight
activation probe (e.g., linear probe on hidden states for polarity-vs-content
signal) to upgrade the mechanism claim, or (b) keep the claim strictly
behavioral in all paper-facing text and cite this limitation explicitly rather
than attempting probing now.

**Priority.** Useful but optional — probing is a legitimate future paper
contribution, not a blocker for the current behavioral claim as long as the
paper's language stays disciplined.

**Decision.** Do not pursue probing now. Keep the claim behavioral; the
existing wording in `docs/TASK_FORMULATION.md` and the mechanism reports
already does this correctly. Flag as future work only.

## C. Task formulation claim

**Claim.** Polarity is a nuisance variable only under candidate-identity
judgment, not under directional-patch judgment.

**Current evidence.**
- `docs/TASK_FORMULATION.md` — states the distinction, ties it to the training
  prompt wording ("compare two related code states and choose the riskier
  side" / "Predict which side contains the security vulnerability" — verified
  candidate-identity framing in both `render_pair` and `build_side_choice_text`
  by grep; no script anywhere frames the task as "does this patch fix or
  introduce").
- `reports/POLARITY_GOLD_CONFOUND.md` — measures the confound that justifies
  treating polarity as nuisance (orientation de-confounded from gold; net
  polarity spurious-but-predictive).

**Current weakness.**
- **The polarity/gold confound has been measured on PrimeVul/DeltaSecommits/
  PatchEval only.** Verified by grep: neither `docs/TASK_FORMULATION.md`,
  `reports/POLARITY_GOLD_CONFOUND.md`, `src/vrf/polarity_gold_confound.py`, nor
  `scripts/analyze_polarity_gold_confound.py` mention CrossVul anywhere. This
  is a real, already-flagged gap: `reports/REPAIR_ANTISYMMETRIC_RESULT_V1.md`'s
  own "side note" on the CrossVul transfer result explicitly says CrossVul's
  higher canonical accuracy and higher flip rate *may* be explained by a
  stronger net-polarity/gold correlation there, and explicitly states "this was
  not separately measured here." That statement has sat unresolved since #54.
- The directional-patch task is excluded by consistent prompt wording
  everywhere checked, but there is no single sentence anywhere outside
  `docs/TASK_FORMULATION.md` that a reviewer can be pointed to as the
  project-wide guarantee; it depends on grep-verified consistency rather than
  an enforced contract (e.g., a test asserting the prompt template never
  contains directional language).

**Likely reviewer attack.** *"You call polarity a nuisance variable on
PrimeVul; does the same de-confounding hold on the other source you tested for
transfer? If CrossVul's polarity/gold correlation is stronger, your CrossVul
repair-transfer numbers are being read through a different confound structure
than your PrimeVul numbers, and the two are not directly comparable."*

**Required next experiment or control.** Run
`scripts/analyze_polarity_gold_confound.py`-equivalent counting directly on
the CrossVul polarity-only-swap audit (`data/processed/
secure_code_crossvul_polarity_only_swap_audit_v1.jsonl`, already built for #54
transfer testing — no new data construction needed, pure counting, no model
run). Report `P(gold=A | net_added)`, `P(gold=A | net_removed)`, and shortcut
accuracy for CrossVul canonical/polarity_only_swap/side_swap, exactly
paralleling the PrimeVul table.

**Priority.** Must-run before serious paper draft. This is cheap (no training,
no new GPU inference, reuses existing tooling near-verbatim) and directly
resolves an already-published open question.

**Decision.** Run this next (see "Recommendation" below) — it is the more
urgent of the two candidate next experiments.

## D. Repair contribution

**Claim.** The antisymmetric readout is a transferable structural fix, but
learned repair v1 is not validated.

**Current evidence.** Complete and internally consistent:
- `#54` PrimeVul in-distribution: antisymmetric-inference canonical accuracy
  0.660→0.733; fine-tuning delta +0.027 over the projection null, McNemar
  p=0.002.
- `#54` CrossVul transfer: fine-tuning delta shrinks to +0.0086, p=0.508 — not
  significant.
- `#55` nuisance-transform transfer: five families, no family clears the
  Bonferroni-corrected threshold (p<0.01), two families reverse sign.
- `#56` consolidated claim boundary across README, `EVIDENCE_HIERARCHY.md`,
  `REPAIR_OBJECTIVE_DESIGN.md`, `RESULTS_INDEX.md`, and `paper/outline.md`,
  verified by a dedicated test (`test_repair_evidence_consolidation.py`) that
  scans for bare forbidden phrases.

**Current weakness.**
- The preregistered seed {7,123} × λ {0.5,1.0,2.0} grid (6 configs) was never
  swept — only one config (seed 7, one λ) was ever trained.
- With the fine-tuning signal already failing *two* independent transfer
  tests, sweeping the grid now carries a real risk: it looks like continuing
  to search for a config that produces a positive result after two negative
  transfer checks, which is close to the definition of chasing significance.

**Likely reviewer attack.** *"Did you just not try hard enough to find a
lambda/seed that works, and give up right when the first config failed
transfer?"* — this is a fair question, but the honest answer is that the
question the grid would answer ("is there *some* config with better transfer")
is a different, weaker claim than "this objective transfers," and running it
now, immediately after two failed transfer legs, without a principled reason
to expect a different config would fix the *mechanism* of failure (sign
reversal on two nuisance families, not just weak significance), is exactly the
kind of result-chasing this audit is meant to prevent.

**Required next experiment or control.** None immediately. If pursued at all,
it should be **objective redesign**, not a hyperparameter sweep of the same
objective: e.g., a stronger/architecturally-different invariance penalty, more
training data, or a training-distribution that includes some of the nuisance
transforms directly (accepting the "regularized to trained transforms"
caveat explicitly, rather than accidentally reproducing it). A hyperparameter
grid on the *same* objective that already reversed sign on two held-out
conditions is unlikely to change the qualitative conclusion and is not a good
use of the next PR.

**Priority.** Do not pursue now (the grid sweep specifically). Objective
redesign is useful-but-optional future work, not a must-run item.

**Decision.** Keep repair v1 closed. Do not restart fine-tuning. Do not sweep
the grid. This is stated explicitly so it is not silently revisited.

## E. Cross-source / external validity

**Claim.** The relational failure and/or structural fix generalizes beyond the
original source.

**Current evidence.**
- `reports/CROSSVUL_ZERO_SHOT_PRIMEVUL_CHECKPOINT.md` — paired-diff accuracy
  degrades but survives genuine open-set source shift (BA 0.8061 vs. 0.8287
  PrimeVul mainline).
- `reports/CROSSVUL_ZERO_SHOT_MATCHED_MIXED_CHECKPOINT.md` — mixed-source
  training generalizes better to CrossVul than single-source.
- `reports/CROSSVUL_LANGUAGE_SHIFT_COMPARISON.md` — language shift adds no
  measurable degradation beyond source shift.
- `#54`/`#55` CrossVul + nuisance-transform repair-transfer results (see D).

**Current weakness.** Same two items already identified above, restated here
because this is where they matter most for an external-validity claim
specifically:
- CrossVul polarity/gold confound not measured (C) — this bears directly on
  how to interpret the CrossVul repair-transfer numbers, since a source-level
  confound difference would explain part of the CrossVul accuracy gap
  independent of any repair or mechanism claim.
- Non-Qwen replication (A) exists for the side-swap/endpoint mechanism
  (CodeBERT, competency-matched) but not for the polarity-vs-label
  decomposition or for the repair architecture. "Generalizes beyond the
  original source" currently means "beyond the original *data* source
  (PrimeVul → CrossVul)," not "beyond the original *model family*."

**Likely reviewer attack.** *"External validity" in your title suggests both
axes — different data and different models — but you've only really nailed
the data axis. Say so explicitly, or do the model-axis work.*

**Required next experiment or control.** Both items are already named above
(C's CrossVul confound measurement; A's CodeBERT label/polarity replication).
No new item beyond those two.

**Priority.** CrossVul confound: must-run (cheap, closes an open question).
CodeBERT mechanism replication: must-run before serious paper draft (bigger,
scope it as its own PR).

**Decision.** Covered by C and A's decisions above; no separate action here.

## F. Human adjudication / evidence localization

**Claim.** Some model disagreements correspond to high-quality relational
failures, while many are insufficient-context cases.

**Current evidence.**
- `reports/PRIMEVUL_MANUAL_ADJUDICATION_STATUS_DASHBOARD.md` — 20 total rows,
  **all 20 human-confirmed** (6 `high_quality_disagreement` + 14
  `insufficient_context`), both tracks marked `complete`.
- Round 3 (`reports/PRIMEVUL_MANUAL_EVIDENCE_ROUND3_PENDING.md`,
  `PRIMEVUL_MANUAL_EVIDENCE_PILOT_FINDINGS_ROUND3.md`) — 14 additional rows,
  **explicitly and repeatedly marked as AI-pilot-only** (`codex_pilot_round3`),
  not yet applied via the same adjudication-apply step used for rounds 1–2.
  The round-3 doc's own claim boundary says: "Nothing in this round is yet
  reviewer-confirmed... must not be described as confirmed until the
  application step above runs."

**Current weakness.**
- **20 human-confirmed rows is small** for any quantitative claim about the
  *rate* of high-quality-disagreement vs. insufficient-context cases in the
  broader pool — it supports "both categories exist and are distinguishable,"
  not a headline proportion.
- The AI-pilot/human-confirmed boundary is correctly and repeatedly stated in
  the round-3 report itself and in `docs/EVIDENCE_HIERARCHY.md` (T5 tier), so
  **exclusion from headline evidence is already enforced in the docs that
  exist**, not a gap in intent — but there is no automated test asserting
  round-3 labels never appear in a headline table if a future PR tries to add
  one.

**Likely reviewer attack.** *"20 examples is an anecdote, not evidence of a
distribution. What fraction of all disagreements are which type?"*

**Required next experiment or control.** Either (a) run round 3's 9
`insufficient_context` rows through the same low-risk bulk-confirmation
procedure already used for rounds 1–2 (the round-3 doc itself says this is
low-risk since none assert a directional claim), growing the confirmed set to
29, or (b) explicitly state in the paper that evidence localization is
diagnostic-scale, not a distributional claim, and stop there.

**Priority.** Useful but optional. Confirming round 3's low-risk rows is cheap
or low-value; either path is defensible. Not on the critical path for the
project's main relational/repair claims.

**Decision.** Do not pursue now. If resumed, it is a small, bounded task
(9 rows, already scoped in the round-3 report), not a new investigation.

## Recommendation

Two experiments were raised as candidates for the next PR:

1. `experiment: competency-matched non-Qwen relational replication`
2. `analysis: CrossVul polarity-gold confound measurement`

**Item 2 (CrossVul confound measurement) is the more urgent next PR.**
Reasoning, grounded in the audit above:

- It is nearly free: no training, no new GPU inference, and no new data
  construction — the CrossVul polarity-only-swap audit dataset already exists
  on disk from #54's transfer testing, and the counting functions
  (`src/vrf/polarity_gold_confound.py`) already exist and are unit-tested.
- It closes a **specific, already-published open question**: the #54 report's
  own text says the CrossVul accuracy/flip-rate difference "may be" explained
  by a stronger confound there and that this "was not separately measured."
  Closing it either firms up or corrects the interpretation of results already
  in the record — higher leverage per unit of work than opening a new line.
- It carries essentially no risk of "chasing a positive result": the outcome
  is a descriptive measurement (contingency tables and a shortcut-accuracy
  number), not a significance test with a preferred direction.

**Item 1 (competency-matched non-Qwen mechanism replication) is real and
higher-priority in the "must-run before serious paper draft" sense** — the
polarity-mechanism claim (B) genuinely is single-architecture, and a paper
draft that presents it as architecture-general without this check would be
overclaiming. It is scoped as its own PR because it is a meaningfully bigger
lift (new audit construction for the label-only/polarity-only conditions on
CodeBERT's tokenizer/length, a new inference run, a new decomposition — though
notably **no new training**, since the CodeBERT checkpoint used in the
existing cross-model audit already exists). It should be the PR after the
CrossVul confound analysis, not before it.

## Priority summary

| Item | Priority | Next action |
| --- | --- | --- |
| CrossVul polarity/gold confound (C, E) | **Must-run** | Next PR: `analysis: CrossVul polarity-gold confound measurement` |
| CodeBERT label-only/polarity-only replication (A, B, E) | **Must-run** | PR after the confound analysis |
| Activation/probing evidence for the mechanism (B) | Useful but optional | Not scheduled; state limitation in paper text instead |
| Repair v1 seed/lambda grid sweep (D) | **Do not pursue now** | Keep repair v1 closed; redesign objective if revisited |
| Round-3 human adjudication completion (F) | Useful but optional | Cheap if resumed (9 rows); not on critical path |
| Diff-size-stratified transformation-family breakdown (A) | Useful but optional | Consider folding into the CodeBERT PR's analysis, not a separate PR |

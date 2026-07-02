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
- ~~The full label-only/polarity-only 2×2 has run on exactly one
  architecture.~~ **Resolved.**
  `reports/CODEBERT_LABEL_POLARITY_MECHANISM_REPLICATION.md` runs the 2×2 on the
  competency-matched CodeBERT checkpoint (canonical 0.677 vs. Qwen 0.660, same
  600 base pairs). The label-vs-polarity **ordering reproduces**: label swap
  inert (phi +0.988 vs. Qwen +0.914), polarity swap disruptive (phi −0.193 vs.
  Qwen −0.094), polarity-only accuracy collapses 0.677→0.352 (Qwen 0.660→0.345).
  The mechanism is now two-architecture behavioral evidence, not single-Qwen.
  (One nuance surfaced: CodeBERT *does* reduce to the crude net-polarity
  line-count shortcut on PrimeVul, ~0.96 row agreement, where Qwen does not
  (~0.57) — same ordering, different functional form. Documented in the report.)
- Transformation-family coverage is broad (label swap, polarity swap, side
  swap, terminal-phrase/endpoint padding, context window, split view, two
  diff algorithms, whitespace/comment) but no report stratifies
  polarity-sensitivity **by diff size** (small vs. large diff_bucket); it is
  implicitly covered by sampling balance, not explicitly analyzed. Still open,
  low-priority.
- Runtime/truncation accounting is consistently maintained (every recent
  builder reports `transformation_introduced_critical_truncation_rows: 0`
  explicitly per condition) — this is in good shape, not a live gap.

**Likely reviewer attack.** *"Your entire polarity mechanism is one decoder
classifier's idiosyncrasy — show me it isn't specific to Qwen's tokenizer,
positional encoding, or training recipe."* Now answered for one additional
architecture (CodeBERT, an encoder — a different family, tokenizer, and
positional scheme), though "two architectures" is broader than one, not
general.

**Required next experiment or control.** The two-architecture replication is
done. A third model family (or a probing/activation study) would broaden
further, but is not a blocker for a bounded, honestly-scoped mechanism claim.

**Priority.** Label/polarity replication: **done**
(`reports/CODEBERT_LABEL_POLARITY_MECHANISM_REPLICATION.md`). Third-family
extension: useful but optional.

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
- ~~The polarity/gold confound has been measured on PrimeVul/DeltaSecommits/
  PatchEval only.~~ **Resolved.** `reports/CROSSVUL_POLARITY_GOLD_CONFOUND.md`
  now measures it on the same 350-pair CrossVul audit used in #54, and the
  result is not a null: CrossVul's net-polarity/gold correlation is
  measurably **stronger** than PrimeVul's (canonical shortcut accuracy `0.855`
  vs. `0.706`; polarity-flip inversion `0.151` vs. `0.312`), and the frozen
  baseline model's predictions track that crude shortcut far more closely on
  CrossVul (`~0.92` vs. `~0.57` row agreement). This means CrossVul's raw
  canonical accuracy and PrimeVul's are **not on comparable footing** and
  should not be read as evidence of stronger secure-code reasoning on the
  unseen source — the `reports/REPAIR_ANTISYMMETRIC_RESULT_V1.md` CrossVul
  transfer numbers should be read with this in mind.
- The directional-patch task is excluded by consistent prompt wording
  everywhere checked, but there is no single sentence anywhere outside
  `docs/TASK_FORMULATION.md` that a reviewer can be pointed to as the
  project-wide guarantee; it depends on grep-verified consistency rather than
  an enforced contract (e.g., a test asserting the prompt template never
  contains directional language). Still open; small and low-priority.

**Likely reviewer attack.** *"You call polarity a nuisance variable on
PrimeVul; does the same de-confounding hold on the other source you tested for
transfer? If CrossVul's polarity/gold correlation is stronger, your CrossVul
repair-transfer numbers are being read through a different confound structure
than your PrimeVul numbers, and the two are not directly comparable."* This
attack is now pre-empted with a measured answer (see above) rather than an
open question.

**Required next experiment or control.** None remaining for the confound
measurement itself. The smaller residual item (an enforced test that the
prompt template never contains directional-patch language, rather than
grep-verified consistency) is optional cleanup, not an experiment.

**Priority.** Confound measurement: **done**
(`reports/CROSSVUL_POLARITY_GOLD_CONFOUND.md`). Directional-language test
guard: useful but optional.

**Decision.** Closed. See "Recommendation" below for what was run and why it
was prioritized first.

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
- `reports/CROSSVUL_POLARITY_GOLD_CONFOUND.md` — CrossVul's net-polarity/gold
  confound, now measured, is stronger than PrimeVul's (see C).

**Current weakness.**
- ~~CrossVul polarity/gold confound not measured~~ **Resolved (see C).** The
  measurement changes how the *other* CrossVul results in this section should
  be read: the `CROSSVUL_ZERO_SHOT_*` accuracy numbers and the #54 CrossVul
  repair-transfer canonical accuracy are all raw canonical accuracy on a
  source now known to carry a stronger presentation shortcut than PrimeVul, so
  "CrossVul accuracy is close to/above the PrimeVul mainline" claims anywhere
  in this project should not be read as "the model reasons about CrossVul
  patches as well as or better than PrimeVul ones" without this caveat. This
  is a reading-caveat on existing evidence, not a reason to retract any
  existing report.
- Non-Qwen replication (A) exists for the side-swap/endpoint mechanism
  (CodeBERT, competency-matched) but not for the polarity-vs-label
  decomposition or for the repair architecture. "Generalizes beyond the
  original source" currently means "beyond the original *data* source
  (PrimeVul → CrossVul)," not "beyond the original *model family*." Still open.

**Likely reviewer attack.** *"External validity" in your title suggests both
axes — different data and different models — but you've only really nailed
the data axis, and even there, your own confound measurement shows the two
data sources aren't comparable on raw accuracy. Say so explicitly, or do the
model-axis work.*

**Required next experiment or control.** The CrossVul confound item is closed.
The remaining item is A's CodeBERT label/polarity replication — no new item
beyond that.

**Priority.** CrossVul confound: **done**. CodeBERT mechanism replication:
must-run before serious paper draft (bigger, scope it as its own PR).

**Decision.** CrossVul confound closed this PR. CodeBERT replication remains
covered by A's decision above.

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

### Update: CrossVul confound measurement complete

Item 2 has been run: `reports/CROSSVUL_POLARITY_GOLD_CONFOUND.md`. It was not
a null result — CrossVul's net-polarity/gold correlation is measurably
**stronger** than PrimeVul's, which changes how CrossVul's raw canonical
accuracy should be read everywhere it is cited in this project (see the
updated C and E sections above). This is a dataset/presentation-structure
finding, not a model-quality claim, and does not by itself invalidate any
existing report — it adds a required reading caveat.

### Update: CodeBERT label/polarity replication complete

Item 1 has been run:
`reports/CODEBERT_LABEL_POLARITY_MECHANISM_REPLICATION.md`. The label-vs-polarity
ordering reproduces on the competency-matched CodeBERT checkpoint (label swap
inert phi +0.988; polarity swap disruptive phi −0.193; polarity-only accuracy
collapses 0.677→0.352), broadening the mechanism to two architectures. A
nuance surfaced worth carrying into any paper draft: CodeBERT reduces to the
crude net-polarity line-count shortcut on PrimeVul (~0.96 row agreement) where
Qwen does not (~0.57) — same behavioral ordering, different functional form.

With both must-run items (C's CrossVul confound, A/B's CodeBERT replication)
now done, the remaining items are all "useful but optional" or "do not pursue
now." **No must-run experiment blocks a first serious paper draft**; the
next step is a judgment call between a third-model-family extension (optional
breadth) and beginning the paper narrative (previously deferred). This audit
does not itself authorize the paper-narrative work.

**Follow-on:** that judgment call is taken up in
`docs/PAPER_READINESS_AUDIT.md`, which audits readiness by paper section and
recommends paper draft alignment as the next step.

## Priority summary

| Item | Priority | Next action |
| --- | --- | --- |
| CrossVul polarity/gold confound (C, E) | **Done** | `reports/CROSSVUL_POLARITY_GOLD_CONFOUND.md` |
| CodeBERT label-only/polarity-only replication (A, B, E) | **Done** | `reports/CODEBERT_LABEL_POLARITY_MECHANISM_REPLICATION.md` |
| Third model-family mechanism extension (A, B) | Useful but optional | Broadens beyond two architectures; not a paper-draft blocker |
| Activation/probing evidence for the mechanism (B) | Useful but optional | Not scheduled; state limitation in paper text instead |
| Repair v1 seed/lambda grid sweep (D) | **Do not pursue now** | Keep repair v1 closed; redesign objective if revisited |
| Round-3 human adjudication completion (F) | Useful but optional | Cheap if resumed (9 rows); not on critical path |
| Diff-size-stratified transformation-family breakdown (A) | Useful but optional | Consider folding into the CodeBERT PR's analysis, not a separate PR |

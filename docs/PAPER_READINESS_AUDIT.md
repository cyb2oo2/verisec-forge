# Paper-Readiness Audit

The two must-run experiments from `docs/EXPERIMENT_COMPLETENESS_AUDIT.md` are
now complete: #58 (CrossVul polarity/gold confound measurement) and #59
(competency-matched CodeBERT label/polarity mechanism replication). This
document audits, **by paper section**, whether the evidence is strong enough
for a serious paper draft, which claims must be softened, and what belongs in
main text vs. appendix.

This is **not** a paper rewrite and adds **no new claims or experiments**. It
assesses readiness of evidence already committed. Each "strongest evidence"
line was checked against the committed report it cites.

## 1. Main thesis readiness

**Thesis.** Pointwise secure-code accuracy can hide relation-violating
behavior induced by patch presentation structure.

**Strongest evidence (ready):**
- Relational instrument: `reports/RELATIONAL_BENCHMARK_V2.md` (VeriPatch-RR:
  canonical/side-swap/suffix/context-pressure tiers, pair-cluster bootstrap,
  marginal-conditioned baselines).
- Qwen mechanism chain: side-swap independence
  (`QWEN_SIDE_SWAP_POSITIONAL_INDEPENDENCE.md`), label-only inert
  (`QWEN_LABEL_ONLY_SWAP_VS_STRUCTURAL_SWAP.md`), polarity-only disruptive
  (`QWEN_POLARITY_ONLY_SWAP_VS_STRUCTURAL_SWAP.md`).
- Confound grounding: `reports/POLARITY_GOLD_CONFOUND.md` (orientation
  de-confounded from gold; net-polarity is a spurious-but-predictive feature).
- Cross-architecture replication: `reports/CODEBERT_LABEL_POLARITY_MECHANISM_REPLICATION.md`
  (competency-matched CodeBERT reproduces the behavioral ordering).

**Verdict: ready for main text.** The thesis is a measurement claim
(pointwise-competent yet relationally inconsistent) supported by an instrument
plus a controlled mechanism decomposition, now on two architectures.

**Stated limit (must accompany the thesis):** this is behavioral evidence
(controlled input interventions on deterministic model predictions), not an
internal-mechanistic proof. No probing/activation study is offered.

## 2. Mechanism claim readiness

**Claim.** The side-order failure is driven by diff-hunk polarity /
removed-added structure more than by prose side labels.

**Evidence:**
- Qwen: label-only phi +0.914 (inert), polarity-only phi −0.094 (disruptive),
  polarity-only accuracy collapse 0.660→0.345.
- CodeBERT: label-only phi +0.988, polarity-only phi −0.193, collapse
  0.677→0.352 — the same ordering, competency-matched (canonical 0.677 vs.
  0.660).
- Functional-form difference: on PrimeVul, CodeBERT closely tracks the crude
  net-polarity line-count shortcut (~0.96 row agreement) while Qwen does not
  (~0.57); on CrossVul both track it heavily (CodeBERT ~0.93, Qwen ~0.92).

**Required cautious wording (main text):**

> The behavioral ordering replicates across Qwen and CodeBERT — prose
> side-label changes are nearly inert while diff-hunk polarity changes are
> highly disruptive — but the functional form differs; this supports a
> cross-architecture behavioral phenomenon, not a shared internal mechanism.

**Verdict: ready for main text as a behavioral claim, with the functional-form
difference stated in the same breath, not buried.** The two-architecture
ordering is the headline; the crude-shortcut divergence is a genuine finding
that a reviewer will otherwise raise as an objection, so it belongs in the main
text as a stated nuance, not only the appendix. The per-variant contingency
tables and phi/p-values are appendix material.

## 3. Cross-source / CrossVul readiness

**Evidence:**
- CrossVul zero-shot paired-diff accuracy survives source shift
  (`CROSSVUL_ZERO_SHOT_PRIMEVUL_CHECKPOINT.md`), but
- CrossVul carries a **stronger** polarity/gold confound than PrimeVul
  (`CROSSVUL_POLARITY_GOLD_CONFOUND.md`: canonical shortcut accuracy 0.855 vs.
  0.706), and
- both Qwen (~0.92) and CodeBERT (~0.93) track the crude shortcut heavily on
  CrossVul.

**Required statement (main text, non-negotiable):**

> CrossVul's higher raw canonical accuracy should not be used as standalone
> evidence of stronger secure-code reasoning; it coincides with a stronger
> measured presentation shortcut that both architectures lean on.

**Verdict: ready, but only as a *caveat-bearing* result.** The CrossVul
material's role in the paper is to (a) demonstrate the confound-measurement
methodology generalizes and (b) guard against misreading source-transfer
accuracy — not to claim cross-source reasoning generalization. The zero-shot
transfer accuracy numbers move to appendix with the confound caveat attached.

## 4. Repair section readiness

**Evidence:**
- Antisymmetric readout is a transferable **structural** fix: side-swap
  equivariance exact by construction; canonical accuracy holds on CrossVul and
  five held-out nuisance families (`REPAIR_ANTISYMMETRIC_RESULT_V1.md`).
- Learned fine-tuning repair v1 is **not validated**: significant
  in-distribution (McNemar p=0.002) but fails both transfer legs — CrossVul
  (p=0.508) and nuisance transforms (0/5 families at Bonferroni p<0.01, 2/5
  sign-reversed).

**Required statement:**

> The antisymmetric readout provides a transferable structural constraint for
> side-order consistency; the fine-tuning increment over this structural null
> does not survive external-source or nuisance-transform transfer, so the
> current learned repair objective remains unresolved.

**Verdict: the structural fix is ready for main text; the learned repair is
future work / unresolved.** Present the antisymmetric readout as a structural
control (its by-construction guarantees plus transfer-confirmed accuracy). Do
not present the fine-tuning increment as a repair. The full four-way
decomposition + McNemar tables are appendix material; `#56`'s consolidated
claim boundary already governs the wording.

## 5. Human adjudication readiness

**Evidence:**
- 20 reviewer-confirmed rows (`PRIMEVUL_MANUAL_ADJUDICATION_STATUS_DASHBOARD.md`:
  6 high-quality-disagreement + 14 insufficient-context, both tracks complete).
- Round 3 (14 rows) is **AI-pilot-only** (`codex_pilot_round3`), explicitly not
  reviewer-confirmed.

**What can be said (appendix):** both categories exist and are distinguishable
under reviewer confirmation — some model disagreements are high-quality
relational failures, many are insufficient-context cases.

**What cannot be claimed:** any *proportion*/distributional statement about how
common each category is (20 rows is diagnostic-scale), and nothing from the
round-3 AI-pilot labels may enter a headline table (T5 in
`docs/EVIDENCE_HIERARCHY.md`).

**Verdict: appendix, diagnostic-scale, optional.** Not on the critical path for
the relational/mechanism/repair claims. If the paper mentions it, frame it as a
qualitative taxonomy illustration with an explicit "not a distribution" caveat.

## 6. Optional experiments remaining

| Item | Classification | Blocks paper draft? |
| --- | --- | --- |
| Third model-family mechanism extension | Future work (breadth) | No |
| Activation/probing evidence for the mechanism | Future work (would upgrade §2 from behavioral to mechanistic) | No |
| Round-3 human adjudication completion | Useful appendix (9 low-risk rows) | No |
| Diff-size-stratified transformation breakdown | Useful appendix | No |
| Repair seed/λ grid sweep | Do not pursue now (result-chasing risk; see `docs/EXPERIMENT_COMPLETENESS_AUDIT.md`) | No |

**None blocks a first serious paper draft.** This confirms the prior. The two
items that would most strengthen the paper if ever done are probing (upgrades
the mechanism claim from behavioral to internal) and a third model family
(broadens §2) — both future work, neither required.

## 7. Proposed paper claim boundary (reusable paragraph)

> We study a **candidate-identity** judgment — given two code states rendered
> as a unified diff, which candidate is riskier — not a directional-patch
> judgment, so diff-hunk polarity is a nuisance variable under our task. We
> show that **pointwise** secure-code accuracy can coexist with
> relation-violating behavior: predictions are nearly inert to prose
> Side A/Side B relabeling yet highly sensitive to diff-hunk polarity, and this
> behavioral ordering **replicates across two competency-matched architectures**
> (a Qwen decoder classifier and a CodeBERT encoder classifier), though their
> functional form differs (CodeBERT tracks a crude net-polarity shortcut where
> Qwen does not) — evidence of a cross-architecture behavioral phenomenon, not
> a shared internal mechanism, and not a universal claim across model families. A
> hard **antisymmetric readout** provides a transferable *structural* constraint
> for side-order consistency; a *learned* fine-tuning objective over that
> structural null did not survive external-source or nuisance-transform
> transfer and remains unresolved. Raw canonical accuracy on an external source
> (CrossVul) is not used as standalone evidence of stronger reasoning, because
> that source carries a measurably stronger presentation shortcut. All
> mechanism evidence is behavioral (controlled input interventions on
> deterministic predictions); we make no internal-mechanistic or
> reasoning-repair claim.

## 8. Recommended next step

Options: (A) paper draft alignment; (B) optional third-model extension; (C)
optional human adjudication expansion; (D) optional diff-size breakdown.

**Recommendation: A (paper draft alignment).** Grounded in evidence readiness,
not storytelling: both must-run experiments are complete, §§1–4 are ready for
main text with stated limits, §§5–6 are appendix/future-work, and no remaining
optional item blocks drafting. B/C/D would each add breadth but none changes
the readiness of the core claims — running them before drafting would be
scope-creep, not a readiness requirement.

The **one substantive risk to manage during drafting** (flagged for the author,
not a blocker): the CodeBERT/Qwen functional-form difference (§2) can be read
by a skeptic as "the two models do different things and the shared ordering is
coincidental." The draft should address this head-on — the shared ordering is
the behavioral claim; the functional-form difference is disclosed as a limit on
the *mechanistic* interpretation — rather than relegating it to a footnote.

This audit does not itself write the paper; it authorizes the *alignment* work
(making `paper/` consistent with the reusable claim boundary in §7) as the next
PR.

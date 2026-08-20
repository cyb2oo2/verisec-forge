# Split-View-Only Training Protocol (Arc 2 Q1)

Pre-registered **before** the training run. This is a mechanism test, not a
method-improvement experiment. It does not revive the locked antisymmetric
epoch-curve claims and does not authorize extra seeds or epochs.

Locked context (unchanged): independent decisions on the original objective
remain at chance; `stop_training = true` for continuing that curve; frozen
pairs carry `0.9216` of the 2→8 antisym lift; glyph polarity *sign* is the
operative inference-time channel.

## Question

Once the `+`/`-` glyph channel is unavailable **from initialization**, does a
3B classifier still learn relational signal beyond the prose polarity
statistic, or is that statistic the practical ceiling?

The existing prose-native pilot (`reports/PROSE_NATIVE_PILOT_V1.md`) trained on
`split_view` but **initialised from a glyph-trained LoRA**. The polarity-balanced
3B curve used the same `split_view` texts but **continued those glyph-exposed
weights**. This run starts from the base Qwen 3B + a fresh LoRA and
classification head. No glyph rendering is seen at any point.

## Data and rendering

| Item | Value |
| --- | --- |
| Train set | `data/processed/secure_code_polarity_balanced_train_scaled_v1.jsonl` |
| Pairs / rows | 2,208 / 4,416 |
| Rendering | `split_view` prose only (`rendering_family = prose`) |
| Glyph channel | absent (no `Unified diff` header; hunk `+`/`-` markers stripped) |
| Balancing | four (gold × net-sign) cells equalised; net polarity carries no gradient |
| Hold-out | v4 evaluation pair keys excluded at construction |
| Exact-mirror | enforced at construction (`swap_mirror_is_exact`) |
| Eval suite | `data/processed/secure_code_relational_benchmark_v4_runtime1024.jsonl` (admissible v4) |

No additional discordant mining. No glyph-family rows in the trainer.

## Model and compute (frozen budget)

| Item | Value |
| --- | --- |
| Backbone | `Qwen/Qwen2.5-Coder-3B-Instruct` |
| Init | **base model + new LoRA + new classification head** |
| Not used | any polarity-balanced, prose-native, or joint-pairwise checkpoint |
| LoRA | r=8, α=32, dropout=0.05, targets `q,k,v,o`, `modules_to_save=["score"]` |
| Objective | same antisymmetric pair-head as the locked curve (BCE on `g(vuln)−g(safe)`) |
| Length | 1024 |
| Seed | 7 (one seed; no second seed in this protocol) |
| Epochs | **4** |
| Micro-batch / accum | 1 / 8 |
| Steps / epoch | 276 |
| **Total optimizer steps** | **1,104** |
| LR | 2e-5, bf16, gradient checkpointing |

This is the locked 4-epoch *compute* point without inheriting glyph-exposed
weights. **Do not add a 5th epoch, a second seed, or more pairs** if the
metrics look promising or unfinished.

## Success and failure (locked before looking)

Primary cell: **prose / polarity-balanced / ALL** (n=308). This is
train-matched `split_view`. Char-net and the prose block-header control are
exactly `0.50` here by construction.

| Rule | Decision |
| --- | --- |
| **Failure (expected under the ceiling claim)** | Independent canonical Wilson 95% CI on the balanced slice **includes** `0.5`, **or** full-set independent does not exceed the v4 char-net / prose control (`0.8502` on 1,202 nonzero-net pairs; locked Arc 2 prose control `0.8433` is the published comparator, not recomputed). |
| **Secondary: degeneracy reappears** | Antisym accuracy on prose / full / discordant moves while independent on that cell stays at chance (0.5-threshold Wilson includes `0.5`). Same pattern as the locked curve, now without any glyph exposure. |
| **Unexpected positive** | Balanced-slice independent Wilson CI **excludes** `0.5` **and** the point is above `0.5`, **and** both-directions-correct also leaves chance. Only this outcome may be considered for a limited follow-up. It is still not a method win. |

All four of independent canonical, independent both-correct, antisym, and
frozen fraction are reported on glyph and prose, full and balanced,
concordant and discordant. Glyph eval is **reference only**.

## What this will not claim

- Not a continuation of the locked 2/3/4/6/8-epoch curve.
- Not a usable scanner or a pair-coupled-decoding method result.
- Not a license to resume pure antisymmetric training on glyph data.
- Not a replacement for the locked `split_view` collapse numbers
  (`0.5133` / `0.4850` vs prose control `0.8433`).

## Stop rule

Write `reports/SPLIT_VIEW_ONLY_TRAINING_V1.md` from this run and **stop**.
No further training until the report is reviewed.

---

## Amendment A — 2026-08-18 (post-run)

**This amendment was written after the run and after the numbers were
observed.** It is recorded here, separately from the pre-registered text
above, so the exact numerical operationalization is not read as having been
fixed before the run. The pre-registered text is unchanged.

### What was underspecified

The success table above says the unexpected-positive branch requires that
"both-directions-correct also leaves chance." **That phrase did not specify a
null for both-directions-correct.** Only the single-decision threshold
(`0.5`) was pre-registered.

### What the implementation did, and why both readings were wrong

1. **Original implementation: `0.5`.** The verdict code reused the single
   decision's `CHANCE = 0.5` for the joint metric. `0.5` is the chance level
   of a *perfectly side-swap-equivariant* random predictor, and equating the
   joint bar to the marginal bar imposes an implicit equivariance hurdle that
   nothing in the protocol asked for: since `both_correct <= 1 - frozen`, the
   gate silently required a frozen fraction below `0.5`, against an observed
   `0.8409`.

   **Correction to an earlier version of this amendment:** that gate was
   *overly restrictive and unjustified*, but it was **not** universally
   unreachable, and the earlier description of it as unexecutable was wrong.
   A sufficiently
   equivariant, accurate system clears it — for example canonical `0.62`,
   swap `0.90`, both-correct `0.60`, frozen `0.32`, with the canonical and
   both-correct Wilson lower bounds above `0.5`. What the old gate actually
   did was **reject the intended positive example** while imposing an
   equivariance-dependent hurdle unrelated to the estimand. It did not
   operationalize the intended usable-decision criterion.
   `tests/test_split_view_only.py::test_old_half_gate_was_restrictive_not_unreachable`
   pins this counterexample so the audit history cannot revert to the false
   description.

2. **First correction: fixed `0.25`.** Replacing the constant with `0.25`
   still conflated an *absolute random baseline* with a *marginal-conditioned
   null*. The uncoupled baseline for both-correct is `p_canonical * p_swap`,
   which equals `0.25` only when both marginals are exactly `0.5`. Gating on a
   fixed `0.25` therefore admits a false positive: canonical `0.80`, swap
   `0.40`, both-correct `0.32` clears `0.25` while the swap decision is *below*
   chance and there is no coupling beyond the marginals (`0.80 × 0.40 = 0.32`
   exactly). That correction also, in its report text, treated a below-`0.25`
   value as evidence of side collapse, which is circular: `both_correct <=
   1 - frozen_fraction` is an identity, so the observation was entailed by the
   frozen fraction before any accuracy was measured.

### Final operationalization

"Both-directions-correct also leaves chance" is adjudicated as a **usable
independent decision**:

| Requirement | Level | Uncertainty |
| --- | --- | --- |
| Balanced canonical accuracy | `> 0.5` | Wilson 95% lower bound `> 0.5` |
| Balanced swap accuracy | `> 0.5` | Wilson 95% lower bound `> 0.5` |
| Full-set independent accuracy | `> 0.8502` | locked control comparison |

This matches the intended estimand: the branch exists to detect a
*single-pass decision a deployed system could emit*, which requires the
per-rendering decision to be better than chance on **each** rendering, not a
joint statistic clearing an arbitrary constant. Both arms of the failure rule
must be escaped — balanced evidence *and* the control comparison.

Joint both-correct remains reported as a diagnostic. `0.25` is retained in the
artifact only as the labelled absolute baseline for two independent 50/50
random decisions. A coupling diagnostic compares observed both-correct against
the marginal-conditioned baseline `p_canonical * p_swap` and is marked
**secondary**; promoting it to a claim would require a pre-specified paired
bootstrap or permutation procedure, which is not performed.

### Outcome adjudication

Exactly one primary outcome is asserted, and it fails closed:

- `indeterminate` — a required metric is missing, a slice violates
  `both_correct = (canonical + swap - frozen) / 2`, or training provenance
  does not match the pre-declared budget.
- `unexpected_positive` — all balanced canonical and swap requirements clear
  chance **and** full-set independent beats the locked control.
- `ceiling_holds` — otherwise, i.e. the protocol's failure arm: balanced
  evidence stays at chance **or** full-set independent fails the control.

`degeneracy_reappears` is demoted to a **secondary mechanistic flag**. It is
recorded alongside the primary outcome and never replaces it.

### Secondary operationalization: the degeneracy threshold

The pre-registered text says only that degeneracy fires when "antisym accuracy
on prose / full / discordant moves while independent on that cell stays at
chance." "Moves" was not quantified. It is operationalized post-run as:

    |antisym_accuracy - independent_canonical_accuracy| >= 0.10
    on prose / full / discordant, while that cell's independent Wilson
    interval still includes 0.5

`0.10` is the named constant `DEGENERACY_DELTA_THRESHOLD` in
`src/vrf/split_view_only.py` and is echoed in the verdict JSON
(`degeneracy_delta_threshold`, with the observed
`degeneracy_observed_delta`) and in the generated report. **It is a secondary
descriptive threshold, not part of the primary pre-registered
success/failure adjudication**, and it neither replaces nor modifies the
primary outcome.

### Control comparison is a point-estimate gate

The full-set arm compares a **point estimate** against the locked `0.8502`
char-net reference. It is not a paired superiority test and no significance is
claimed in either direction. It is retained as a conservative follow-up gate,
not as a headline comparison.

### Effect on the published result

**None.** The observed run remains `ceiling_holds` with `stop_training: true`
under every operationalization considered — balanced canonical `0.5487`
(Wilson `[0.4929, 0.6033]`, includes `0.5`) fails the first arm and full-set
independent `0.5674` fails the control arm independently.

This amendment **does not authorize further training**, additional epochs,
extra seeds, or mined pairs. The stop rule above is unchanged.

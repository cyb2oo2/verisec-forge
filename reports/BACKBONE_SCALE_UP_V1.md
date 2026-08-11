# Backbone Scale-Up: the discordant ceiling was capacity, not the task

Two new backbones, each carrying the full four-stage LoRA lineage of the 1.5B
line, evaluated under `docs/PURIFIED_EVALUATION_PROTOCOL.md`.

**All 1.5B artifacts are unchanged.** Every artifact produced here is written to
a new path, and the evaluator used was first checked against the published 1.5B
predictions, which it reproduces bit-for-bit (`0.1944` / `+0.0713` for the
prose-native pilot, `0.2833` / `+0.1001` for the balanced 552/cell × 2ep run).

| | model | precision | params |
| --- | --- | --- | --- |
| reference | `Qwen/Qwen2.5-Coder-1.5B-Instruct` | bf16 | 1.5B |
| **arm A** | `Qwen/Qwen2.5-Coder-3B-Instruct` | bf16 | 3.09B |
| **arm B** | `Qwen/Qwen2.5-Coder-7B-Instruct` | nf4 (double-quant, bf16 compute) | 7.62B |

## Verdict

**The `0.26–0.28` discordant plateau was a capacity limit of the 1.5B backbone.
It is not a property of the task or the data under the purified protocol.**

Both larger backbones break it decisively, on an otherwise identical recipe.

| Success criterion (as set for this phase) | Result |
| --- | --- |
| 1. Discordant accuracy moves clearly beyond `0.26–0.28` | **met** — 3B `0.4333` / `0.4167` (two seeds), 7B `0.3833`, vs a `0.2611–0.2833` band across four 1.5B runs |
| 2. Without collapsing concordant performance | **met** — 3B `0.8924` / `0.9061`, 7B `0.8845`, vs 1.5B `0.9168` |
| 3. Balanced-slice advantage over the control stays positive | **met** — 3B `+0.1688` (`p=3.13e-08` / `p=5.26e-09`), 7B `+0.1623` (`p=2.86e-09`) |

Under the phase's own rule this qualifies as promising. The 3B is the headline:
it is the clean bf16 scale point, the stronger of the two, and the only one
seed-replicated.

**The two bands are disjoint.** Four 1.5B runs span `0.2611–0.2833`; two 3B seeds
span `0.4167–0.4333`. There is no overlap and a `0.13` gap between them.

**The scaling is not monotonic.** The 4-bit 7B lands *between* the 1.5B and the
3B. See §"Does it keep scaling?".

## What was run

Four stages per backbone, each a config-level port of the corresponding 1.5B run
with only the backbone swapped. Same datasets, same LoRA (r=8, α=32, q/k/v/o,
`modules_to_save=["score"]`), same seeds, same schedules, same length 1024.

| Stage | Objective | Data | Schedule |
| --- | --- | --- | --- |
| S0 | binary CE, glyph pair-diff | 3,000 PrimeVul pairs | 1 ep, lr 5e-5, bs 1 × ga 4 |
| S1 | joint-pairwise margin | 3,000 pairs | 1 ep, lr 2e-5, bs 1 × ga 8 |
| S2 | prose-native antisymmetric | 1,736 pairs / 3,472 rows | 1 ep, lr 2e-5, seed 7 |
| S3 | **polarity-balanced antisymmetric** | 2,208 pairs (552/cell × 4) | 2 ep, lr 2e-5, seed 7 |

S3 training mixture: PrimeVul time-disjoint train, PatchEval all, DeltaSecommits
all (v2), CrossVul non-held-out; four `(gold × net-sign)` cells equalised at 552
so the polarity shortcut carries no gradient. `split_view` prose only.

Configs: `configs/{cls_secure_code_primevul_qwen25coder3b_lora_pair_diff_only_3000_v1,research_primevul_joint_pairwise_qwen3b_v1,research_prose_native_pilot_qwen3b_v1,research_polarity_balanced_scaled_2ep_qwen3b_v1}.json`
and the matching `*_qwen7b_v1.json` set.

| | S1 loss | S2 loss | S3 loss | S1 s | S2 s | S3 s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1.5B | — | `0.463` | `~0.65` | — | 451 | — |
| 3B | `0.7705` | `0.3841` | `0.6271` | 2,121 | 970 | 2,966 |
| 7B | `0.8377` | `0.4281` | `0.6396` | 1,733 | 1,012 | 2,829 |

### Tokenizer identity verified

All three backbones produce byte-identical token sequences on the suite (0
mismatches / 400 texts, vocab 151,665 each). The v4 runtime suite and its
`runtime_accounting` transfer unchanged. This is a pure scale comparison, not
scale confounded with tokenizer or model family.

### Both larger backbones are genuinely stronger upstream

| Stage | metric | 1.5B | 3B | 7B |
| --- | --- | ---: | ---: | ---: |
| S0 | binary pair-diff accuracy (1,800 pairs) | `0.8156` | `0.8444` | `0.8472` |
| S0 | F1 | `0.8184` | `0.8467` | `0.8503` |
| S1 | pair orientation accuracy (827 pairs) | `0.8283` | `0.8513` | `0.8549` |
| S1 | independent threshold both-correct | `0.6155` | `0.7134` | `0.7025` |

The larger models were already better on the surface task before any relational
stage ran, so a null result would not have been attributable to a weaker model.

## Decisive metric

Population estimator over the 1,202 pairs with defined polarity. Cells:
`gold=A,net=+` 507, `gold=A,net=−` 90, `gold=B,net=+` 90, `gold=B,net=−` 515.

| Backbone | System | rendering | concordant | **discordant** | balanced Δ | 95% CI |
| --- | --- | --- | ---: | ---: | ---: | --- |
| 1.5B | prose-native | prose | `0.9481` | `0.1944` | `+0.0713` | `[+0.0425, +0.1022]` |
| 1.5B | balanced | prose | `0.9168` | `0.2833` | `+0.1001` | `[+0.0668, +0.1345]` |
| 3B | prose-native | prose | `0.9618` | `0.2000` | `+0.0809` | `[+0.0522, +0.1117]` |
| **3B** | **balanced, seed 7** | **prose** | `0.8924` | **`0.4333`** | **`+0.1629`** | `[+0.1260, +0.2010]` |
| **3B** | **balanced, seed 123** | **prose** | `0.9061` | **`0.4167`** | **`+0.1614`** | `[+0.1252, +0.1986]` |
| 7B | prose-native | prose | `0.9481` | `0.2278` | `+0.0880` | `[+0.0573, +0.1196]` |
| **7B** | **balanced** | **prose** | `0.8845` | **`0.3833`** | **`+0.1339`** | `[+0.0971, +0.1712]` |
| 1.5B | balanced | glyph | `0.9325` | `0.2000` | `+0.0662` | `[+0.0359, +0.0975]` |
| 3B | balanced, seed 7 | glyph | `0.9648` | `0.1944` | `+0.0796` | `[+0.0511, +0.1097]` |
| 3B | balanced, seed 123 | glyph | `0.9589` | `0.2111` | `+0.0850` | `[+0.0554, +0.1159]` |
| 7B | balanced | glyph | `0.9648` | `0.1833` | `+0.0741` | `[+0.0465, +0.1035]` |

Disjoint-half replication — the only genuinely independent replication available
from one suite: 3B seed 7 `+0.1722` / `+0.1535`, 3B seed 123 `+0.1649` / `+0.1578`,
7B `+0.1449` / `+0.1231`. 25/25 pooled seed draws positive for all three.

### Seed replication at 3B

Config: `configs/research_polarity_balanced_scaled_2ep_qwen3b_seed123_v1.json`.
Seed 7 → 123 for **both cell sampling and training**, matching the protocol of
the 1.5B replication. Stage 3 only: it re-uses the *same* seed-7 prose-native
stage-2 checkpoint, so stage 2 is held fixed and only the balanced stage varies.
Data rebuilt at seed 123 (`secure_code_polarity_balanced_train_scaled_seed123.jsonl`,
2,208 pairs). Train loss `0.6179` vs seed 7's `0.6271`.

| Metric (prose) | seed 7 | seed 123 | spread |
| --- | ---: | ---: | ---: |
| concordant | `0.8924` | `0.9061` | `0.0137` |
| **discordant** | `0.4333` | `0.4167` | `0.0166` |
| balanced Δ | `+0.1629` | `+0.1614` | `0.0015` |
| balanced slice both-correct | `0.6656` | `0.6656` | `0.0000` |

The effect replicates. Discordant spread across seeds is `0.0166`, comparable to
the 1.5B's own seed spread (`0.2778` / `0.2722`).

> **How independent is this?** Only partly, and the balanced design makes that
> unavoidable. Jaccard between the two draws is `0.399` over pairs. The two
> *discordant* cells are limiting — 552 available, 552 taken — so they overlap
> 95%; the two concordant cells overlap 9%. This run therefore varies training
> stochasticity and the concordant sample, but not the discordant examples that
> the decisive metric is computed on. It is a seed replication, not an
> independent sample of discordant pairs. The 7B arm, trained on the same data
> with a different backbone, is the better check on that axis.

> **The identical balanced-slice figures are a coincidence, not a duplicated
> file.** The two checkpoints share only 23 of 4,980 probabilities and differ on
> 105 hard predictions; on the 308-pair balanced slice they disagree on 20 pairs
> and happen to net to exactly 205 correct each (10 flips each way). Per-source
> figures coincide for the same reason.

**Independently recomputed.** The 3B headline was re-derived from raw predictions
with a different net-polarity derivation (glyph `+`/`-` lines rather than the
evaluator's per-rendering character helper) and a hand-written antisymmetric
decode: concordant `0.8940`, discordant `0.4326` (77/178), delta `+0.1633`.

### This is not the INLP dilution mode

INLP set the discriminating test: a decision drifting toward random raises
discordant accuracy while the balanced delta stays flat. Here the balanced delta
**rises** — 1.5B `+0.1001` → 3B `+0.1629`. Discordant gains `+0.1500` while
concordant loses only `-0.0244`. The gain is six times the loss.

### Capacity alone is not the mechanism

Both larger prose-native pilots sit near the old plateau (3B `0.2000`, 7B
`0.2278`). On the *glyph* rendering — which the balanced stage never trains on —
the larger balanced checkpoints are at `0.1944` and `0.1833`, i.e. unchanged,
while their concordant accuracy *improves* to `0.9648`. Off the trained
rendering, a bigger model is simply a better polarity-follower.

The gain appears only where extra capacity and the shortcut-free gradient meet.
Neither ingredient alone produces it.

## Balanced evaluation slice (308 pairs)

| Family | System | both-correct | Δ vs control | 95% CI | sign test |
| --- | --- | ---: | ---: | --- | --- |
| prose | control | `0.4968` | — | — | — |
| prose | 3B prose-native | `0.5649` | `+0.0682` | `[+0.0292, +0.1071]` | `p=0.00145` |
| prose | 7B prose-native | `0.5779` | `+0.0812` | — | — |
| prose | 1.5B balanced | `0.5974` | `+0.1006` | `[+0.0552, +0.1461]` | `p=3.3e-05` |
| prose | **7B balanced** | `0.6591` | `+0.1623` | `[+0.1104, +0.2143]` | `p=2.86e-09` |
| prose | **3B balanced, seed 7** | **`0.6656`** | **`+0.1688`** | `[+0.1104, +0.2240]` | `p=3.13e-08` |
| prose | **3B balanced, seed 123** | **`0.6656`** | **`+0.1688`** | `[+0.1136, +0.2240]` | `p=5.26e-09` |
| glyph | control | `0.5000` | — | — | — |
| glyph | 7B balanced | `0.5649` | `+0.0649` | `[+0.0260, +0.1039]` | `p=0.00166` |
| glyph | 3B balanced, seed 7 | `0.5812` | `+0.0812` | `[+0.0455, +0.1201]` | `p=2.24e-05` |
| glyph | 3B balanced, seed 123 | `0.5877` | `+0.0877` | `[+0.0487, +0.1266]` | `p=1.43e-05` |

> **Numeric collision on the 3B prose-native row, not a resurrection.** Its
> `+0.0682` rounds to the same value as the withdrawn Arc 1 claim "the detector
> beats a semantics-free control by `+0.0682`"
> (`docs/RESEARCH_INTEGRITY_REMEDIATION.md`), and to the 1.5B pilot's `+0.068`.
> They are unrelated quantities. The withdrawn one was a full-population
> detector-vs-line-count margin, **superseded** by the character-level control at
> `+0.0008`, CI `[-0.0202, +0.0222]`. Neither supports the other, and none of
> them is the result this report turns on.

### Contamination check

CrossVul (minus the 350 held-out v4 keys) is training data for all three
balanced checkpoints. Balanced slice, prose, both-directions-correct:

| Source | zero-shot? | n | control | 1.5B | 3B | 7B |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| PatchEval | **nearly**¹ | 76 | `0.5000` | `0.5789` | **`0.7105`** | `0.6579` |
| DeltaSecommits | **nearly**¹ | 60 | `0.5000` | `0.6167` | `0.6667` | `0.6000` |
| PrimeVul | yes | 68 | `0.4853` | `0.5735` | `0.6471` | `0.6471` |
| CrossVul | **no** | 104 | `0.5000` | `0.6154` | `0.6442` | **`0.7019`** |

> ¹ **Correction, added after this report was published.** PatchEval and
> DeltaSecommits were labelled `zero-shot: yes` here. They are not strictly
> zero-shot. The training-set builder excluded held-out pairs by `pair_key` alone,
> and both sources assign *several keys to identical content*
> (`patcheval-18-0` == `patcheval-677-0`; `deltasecommits-222` and `-223` both ==
> `deltasecommits-221`), so evaluation pairs re-entered training under a second
> key. Across the whole v4 suite, 37 pairs have a training-side content twin —
> DeltaSecommits 17, CrossVul 13, PatchEval 7. **On the 308-pair balanced slice
> this table reports, 11 are affected: CrossVul 7, PatchEval 3, DeltaSecommits 1.**
> Each published balanced checkpoint trained on 32 (seed 7) or 36 (seed 123) such
> twins. **PrimeVul is unaffected and remains genuinely zero-shot**, as does the
> `0.4853` control column.
>
> **This does not change any conclusion in this report.** Of the 180 discordant
> evaluation pairs the decisive metric rests on, 3 have a training twin, bounding
> the memorisation bias at `0.0167` — against measured seed spreads of
> `0.0674`–`0.0778`. The bound was tested directly: `MINED_DISCORDANT_SUPPLY_V1.md`
> retrained the 3B on a decontaminated set and the balanced Δ mean moved by
> `+0.0009` (`+0.2166` → `+0.2175`), with discordant accuracy *rising* rather than
> falling. Removing the contamination cost nothing, so it was not inflating these
> numbers.
>
> Fixed in `pair_content_fingerprint`
> (`src/vrf/relational_benchmark.py`), enforced by
> `scripts/build_prose_native_training_set.py`, and checked independently by
> `scripts/audit_training_pool_contamination.py`. Evidence:
> `reports/v4_suite_content_leak_check.json`,
> `reports/decontamination_verification.json`.

For the **3B the gain is weakest on the contaminated source**, which rules out
leakage as its explanation. For the **7B it is strongest there**, so the 7B's
aggregate is somewhat inflated by contamination — though all three zero-shot
sources still clear the control by `+0.10` to `+0.16`.

That last sentence should now read "the two nearly-zero-shot sources and
PrimeVul"; the margins themselves are unchanged, and the `+0.10`–`+0.16` range
still holds.

## Full clean set (1,245 pairs)

| Family | System | both-correct | Δ vs control | 95% CI |
| --- | --- | ---: | ---: | --- |
| prose | control | `0.8273` | — | — |
| prose | 1.5B balanced | `0.8064` | `-0.0209` | `[-0.0402, -0.0016]` significant |
| prose | 3B balanced, seed 7 | `0.8120` | `-0.0153` | `[-0.0369, +0.0072]` **not significant** |
| prose | 3B balanced, seed 123 | `0.8185` | `-0.0088` | `[-0.0297, +0.0129]` **not significant** |
| prose | 7B balanced | `0.7976` | `-0.0297` | `[-0.0522, -0.0072]` significant |
| prose | 3B prose-native | `0.8313` | `+0.0040` | `[-0.0112, +0.0193]` |
| glyph | control | `0.8281` | — | — |
| glyph | 3B balanced | `0.8386` | `+0.0104` | `[-0.0048, +0.0257]` |
| glyph | 7B balanced | `0.8394` | `+0.0112` | `[-0.0040, +0.0265]` |

The 1.5B paid a statistically significant full-set penalty for balanced
training. The 3B does not — its prose deficit is no longer distinguishable from
zero, and on glyph it is nominally ahead of the control. Capacity largely absorbs
the trade. The 7B does not absorb it.

## Primary question 2: is polarity still linearly decodable? Yes — more so

`reports/polarity_probe_qwen{3b,7b}.json`, same protocol as
`reports/POLARITY_PROBE_DIAGNOSTIC.md` (pair-disjoint split, last non-pad
position of the final hidden layer, val positive rate exactly `0.5000`).

| Checkpoint | family | linear | MLP |
| --- | --- | ---: | ---: |
| 1.5B glyph baseline | prose | `0.6925` | `0.7133` |
| 1.5B prose-native | prose | `0.8296` | `0.8296` |
| 3B prose-native | prose | `0.9169` | `0.9127` |
| 3B balanced | prose | `0.9044` | `0.8947` |
| 7B prose-native | prose | `0.9072` | `0.9127` |
| 7B balanced | prose | `0.8740` | `0.8809` |
| 3B balanced | glyph | `0.9169` | `0.9169` |
| 7B balanced | glyph | `0.9321` | `0.9224` |

**The shortcut did not go away — it got easier to read.** Polarity is more
linearly decodable from both larger backbones than from any 1.5B checkpoint.

This is the most consequential finding here, because it separates two things the
1.5B evidence had conflated. The 1.5B argument ran: polarity is `0.90`-decodable,
INLP shows it is redundantly encoded, discordant accuracy will not move,
therefore *the model has no content-based relational representation to fall back
on*. The scale-up shows the first three facts can all hold while the conclusion
fails. **Shortcut presence is not shortcut reliance.** The larger models carry the
polarity feature at least as strongly and simply rely on it less, because they
have something else to use.

That also retires the implied remedy. Three prior interventions (gradient
reversal, INLP, glyph-stripping) tried to *remove* the shortcut, and INLP only
raised discordant accuracy by destroying the decision. What worked removed the
shortcut's **gradient** and added capacity, leaving the feature itself intact.

## Limitation: independent inference is still degenerate

Unchanged from the 1.5B, and not to be glossed over.

| System | rendering | independent canonical | equivariance | both-correct |
| --- | --- | ---: | ---: | ---: |
| 3B balanced | prose | `0.5213` | `0.0635` | `0.0578` |
| 7B balanced | prose | `0.5398` | `0.1269` | `0.1181` |
| 3B balanced | glyph | `0.7807` | `0.6586` | `0.6008` |

Per-rendering decisions on prose are effectively frozen — the 3B gives the same
answer on canonical and swap for ~94% of pairs. **Every number in this report
flows through the antisymmetric projection.** A larger backbone did not fix this.

## Does it keep scaling? Not cleanly

| Backbone | precision | prose discordant |
| --- | --- | ---: |
| 1.5B | bf16 | `0.2833` |
| 3B | bf16 | `0.4333` |
| 7B | nf4 | `0.3833` |

Two readings are consistent with this and the data here cannot separate them:

1. **Quantization cost.** The 7B is the only 4-bit arm. Its S3 training loss is
   higher than the 3B's (`0.6396` vs `0.6271`) despite 2.5× the parameters, and
   its S0/S1 gains over the 3B are marginal (`+0.003`) where the 1.5B→3B gains
   were large (`+0.029`, `+0.023`). That pattern is what quantization damage
   looks like.
2. **A genuine plateau past 3B**, with 7B noise on 180 discordant pairs.

Settling this needs a bf16 7B, which does not fit a 12 GB card. **The bf16 3B
remains the clean scale point, and the 7B should be read as an independent
confirmation that the ceiling breaks, not as a measurement of the scaling
exponent.**

## The ledger, updated

| Intervention | backbone | prose discordant | moved the decisive metric? |
| --- | --- | ---: | --- |
| glyph-trained baseline | 1.5B | — (`0.1833` glyph) | — |
| prose-native training | 1.5B | `0.1944` | no |
| gradient-reversal λ=0.1 / 1.0 | 1.5B | `0.2000` / `0.1944` | no |
| INLP, 12 rounds | 1.5B | `0.5056` | only by destroying the decision (conc `0.6037`) |
| polarity-balanced 254/cell | 1.5B | `0.2778` | yes, `+0.08`, then saturated |
| polarity-balanced 552/cell × 1ep | 1.5B | `0.2611` | no further |
| polarity-balanced 552/cell × 2ep | 1.5B | `0.2833` | no further |
| prose-native training | 3B | `0.2000` | no |
| prose-native training | 7B | `0.2278` | no |
| **polarity-balanced 552/cell × 2ep** | **7B nf4** | **`0.3833`** | **yes, `+0.10`** |
| **polarity-balanced 552/cell × 2ep, seed 123** | **3B bf16** | **`0.4167`** | **yes, `+0.13`** |
| **polarity-balanced 552/cell × 2ep, seed 7** | **3B bf16** | **`0.4333`** | **yes, `+0.15`** |

The saturation reported in `POLARITY_BALANCED_SCALED_2EPOCH.md` was real *at that
scale*. It was not saturation of the method.

## Correction to the prior conclusion

`POLARITY_BALANCED_SCALED_2EPOCH.md` concluded: "this model has no content-based
relational representation to fall back on. Removing the shortcut's gradient
relocates it to a slightly different solution; it does not reveal a better one
underneath." Its first-ranked next step was capacity.

The capacity test has now run and the first clause was too strong. Removing the
shortcut's gradient *does* reveal a better solution underneath — there just was
not one underneath a 1.5B. That report's ranking was correct; its diagnosis of
the cause was not, and this report supersedes it on that point only. Every 1.5B
measurement it reports stands unchanged and is reproduced bit-for-bit by the
evaluator used here.

## Claim boundary

The 3B headline is **seed-replicated** (`0.4333` / `0.4167`, balanced Δ `+0.1629`
/ `+0.1614`), varying both cell sampling and training seed, with stage 2 held
fixed. That replication is only partly independent: the limiting discordant cells
overlap 95% between draws by construction, so it does not resample the pairs the
decisive metric is computed on.

**The 7B arm remains seed 7 only**, and stages S0–S2 of both new arms are single
runs — only S3, the stage the claim rests on, has been repeated.

Prose-only training rendering, one model family (Qwen2.5-Coder), length 1024,
LoRA r=8 on q/k/v/o — a rank the larger backbones may under-use. Evaluated on
1,245 held-out pairs across four sources; balanced-slice figures rest on 308
pairs and the discordant cells on 180 pairs, so `0.4333` is 78/180 and its
sampling error is not small. CrossVul rows are not zero-shot for any balanced
checkpoint; for the 7B the contaminated source carries the largest gain. **Nor
are PatchEval and DeltaSecommits strictly zero-shot** — see the correction under
§"Contamination check". Only PrimeVul is.

The 7B arm is nf4 throughout — training, inference and probing — which is a
deliberate confound the 3B arm does not carry. Stage 0 ran bf16 in both new arms
where the 1.5B ran fp32 (a 3B in fp32 exceeds the 12 GB card); every later stage
in all three arms was already bf16.

Discordant `0.4333` remains below the `0.5` chance line: the model is still wrong
on ~57% of pairs where polarity misleads. This is a large movement on a metric
that had not moved across four prior interventions. It is not a demonstration of
relational competence.

## Next, in order

1. ~~Seed replication of the 3B S3~~ — **done**, see §"Seed replication at 3B".
2. **Mine more discordant pairs.** This is now the binding constraint on both the
   method and its evaluation: the balanced design exhausts the discordant cells
   (552 available, 552 used), which is why a seed redraw cannot resample them and
   why the decisive metric rests on only 180 evaluation pairs. More discordant
   supply would strengthen training *and* measurement at once.
3. **Re-scale the balanced set at 3B.** The 1.5B saturated at 552/cell; that
   saturation is now known to be capacity-bound and may not hold at 3B. Blocked
   on (2) — 552/cell is the current ceiling of the pool.
4. **Higher LoRA rank at 3B**, to test whether r=8 is now the binding constraint
   rather than the backbone.
5. A bf16 7B (or 8-bit) on hardware with more than 12 GB, to separate
   quantization cost from a genuine plateau.

## Reproducing

Both lineages are driven entirely by committed configs:

    # arm A (bf16)
    python scripts/train_eval_codexglue_classifier.py --config configs/cls_secure_code_primevul_qwen25coder3b_lora_pair_diff_only_3000_v1.json
    python scripts/train_joint_pairwise_classifier.py --config configs/research_primevul_joint_pairwise_qwen3b_v1.json
    python scripts/train_antisymmetric_repair.py     --config configs/research_prose_native_pilot_qwen3b_v1.json
    python scripts/train_antisymmetric_repair.py     --config configs/research_polarity_balanced_scaled_2ep_qwen3b_v1.json

    # arm B (nf4): same four commands against configs/*_qwen7b_v1.json,
    # and add --load-in-4bit to predict_veripatch_rr.py / probe_polarity_representation.py

Long GPU runs should be budgeted so the card is not saturated — the display
adapter is the same device:

    VRF_GPU_MEMORY_FRACTION=0.60 VRF_GPU_THROTTLE_MS=30 python scripts/... --batch-size 1

Both variables are unset by default, so every result above reproduces without
them.

`scripts/train_eval_codexglue_classifier.py` was restored from commit `06da8a2^`
(pruned in `06da8a2`); it is required to rebuild stage 0 for any new backbone.

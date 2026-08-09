# Hard-Negative Construction — the ceiling break is compute, not hardness

Builder: `scripts/build_hard_negative_training_set.py`
Datasets: `data/processed/secure_code_hard_negative_{train_v1,control_train_v1,train_seed123}.jsonl`
Configs: `configs/research_hard_negative_{hard,control}_qwen3b_v1.json`,
`configs/research_hard_negative_hard_qwen3b_seed123_v1.json`,
`configs/research_polarity_balanced_scaled_3ep_qwen3b_v1.json`
Artifacts: `reports/veripatch_rr_hard_negative_slice.json`,
`reports/secure_code_hard_negative_*_summary.json`

Evaluated under `docs/PURIFIED_EVALUATION_PROTOCOL.md`. All prior artifacts unchanged.

## Verdict

**The 0.42 discordant ceiling breaks — but not because of hard negatives.** One
additional epoch on the *unchanged, published* 2,208-pair balanced set moves
prose discordant accuracy from `0.4326` to `0.5393`. Hard-negative enrichment
adds a targeted effect on the subpopulation it was designed for, and that effect
does not survive a seed change intact.

| Success criterion | Result |
| --- | --- |
| Discordant clearly above the 0.42 ceiling | **met** by all three new runs (`0.5281`–`0.6067`) |
| Concordant remains healthy | met for the compute control (`0.8567`); **strained** for the hard arm (`0.7880`) |
| Balanced-slice advantage preserved or improved | met — `+0.1633 → +0.1974`…`+0.2086` |
| …**attributable to hard negatives** | **no** — the compute control reproduces most of it |

## A correction to the phase premise

The brief specified mining pairs whose *content difference is subtle*. Measured
against the published 3B checkpoint, that is not where the model fails.
Discordant accuracy by removed/added similarity quartile is non-monotonic, and
the subtlest quartile is **not** the worst:

| Quartile | similarity | n | accuracy |
| --- | --- | ---: | ---: |
| Q1 (wholesale rewrite) | 0.00–0.16 | 44 | `0.2955` |
| Q2 | 0.16–0.48 | 44 | `0.5227` |
| Q3 | 0.49–0.74 | 44 | `0.5227` |
| Q4 (**subtlest**) | 0.75–0.99 | 46 | `0.3913` |

Splitting on **edit shape** instead isolates the failure almost completely:

| Discordant subpopulation | n | baseline accuracy |
| --- | ---: | ---: |
| **pure add/delete** (one block empty) | 28 | **`0.0714`** |
| mixed edit | 150 | `0.5000` |

The published `0.4326` is *chance on mixed edits* blended with *systematic
inversion on pure additions and deletions* — 2 correct of 28, far below the 0.5
chance line (binomial `p ≈ 1e-6`). Those are the cases where net polarity is
maximally confident and wrong. The construction therefore targets edit shape,
not content subtlety.

## Construction

Real pairs only; nothing synthesised. Base = the published 552/cell × 4 balanced
set, reused verbatim. Enrichment = 75 pure add/delete pairs **per (gold × net-sign)
cell**, oversampled ×4.

**The enrichment block is itself cell-balanced by design.** Enriching pure
add/delete pairs only in the discordant cells would have made "is one block
empty?" predictive of gold — a fresh surface heuristic of exactly the kind the
phase constraints forbid. Verified in the emitted set:

| Cell | base pairs | enrichment pairs | of which pure |
| --- | ---: | ---: | ---: |
| gold=A, net=+ | 552 | 300 | 300 |
| gold=A, net=− | 552 | 300 | 300 |
| gold=B, net=+ | 552 | 300 | 300 |
| gold=B, net=− | 552 | 300 | 300 |

Neither net polarity nor the pure/mixed marker is predictive of gold. Every
enrichment pair was re-checked against `swap_mirror_is_exact` at selection and
is disjoint from the v4/v5 suite and all four eval pools.

### Controls

| Arm | training set | steps | isolates |
| --- | --- | ---: | --- |
| baseline (published) | 2,208 × 2ep | 552 | — |
| **compute control** | **2,208 × 3ep** | 828 | compute alone, set held fixed |
| enrichment control | 3,408 × 2ep (mixed edits) | 852 | set size, hardness removed |
| hard arm | 3,408 × 2ep (pure add/del) | 852 | hardness |

## Decisive metric

Population estimator, 1,197 pairs with defined polarity, prose rendering.

| System | concordant | **discordant** | balanced Δ | pure add/del | mixed |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline 2,208 × 2ep | `0.8940` | `0.4326` | `+0.1633` | 2/28 | 75/150 |
| **compute control 2,208 × 3ep** | `0.8567` | **`0.5393`** | `+0.1980` | 8/28 | 88/150 |
| enrichment control 3,408 × 2ep | `0.8891` | `0.5281` | **`+0.2086`** | 7/28 | 87/150 |
| hard arm, seed 7 | `0.7880` | **`0.6067`** | `+0.1974` | **17/28** | 91/150 |
| hard arm, seed 123 | `0.8008` | `0.5506` | `+0.1757` | 11/28 | 87/150 |

Glyph rendering (never trained on) barely moves: `0.2135` → `0.2022`–`0.2303`.

### What the controls establish

1. **Compute is the lever.** The compute control changes *nothing* about the
   data — same 2,208 pairs, same cells, same seed — and recovers `0.5393` of the
   `0.6067` peak. Most of the ceiling break needs no new data at all.
2. **Extra data adds nothing beyond compute.** The enrichment control has 55%
   more pairs at matched steps and lands at `0.5281`, *below* the compute
   control.
3. **Hardness has a real but narrow effect.** On the targeted subpopulation the
   hard arm reaches 17/28 (seed 7) and 11/28 (seed 123) against the compute
   control's 8/28. Directionally consistent, but noisy on 28 pairs.
4. **It does not replicate tightly.** Discordant `0.6067` → `0.5506` across
   seeds, a spread of `0.0561` — versus `0.0166` for the earlier 3B seed
   replication. Seed 123 lands on the compute control. The aggregate balanced
   delta straddles it (`+0.1757` / `+0.1974` vs `+0.1980`).
5. **Hardness costs concordant accuracy.** `0.7880`–`0.8008` against the compute
   control's `0.8567` — the largest concordant sacrifice in this line of work.

Had the hard arm been run without the compute control, the honest-looking
headline would have been "hard negatives break the ceiling, `+0.034` balanced
delta." That claim would have been wrong in its attribution.

## Required reporting

Balanced slice (308 pairs) and full set (1,245), both-directions-correct:

| Slice | Family | control | compute ctrl | hard arm | hard − control | 95% CI |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| balanced | prose | `0.4968` | `0.6981` | `0.7273` | `+0.2305` | `[+0.1623, +0.2955]` |
| balanced | glyph | `0.5000` | `0.5844` | `0.5909` | `+0.0909` | `[+0.0519, +0.1299]` |
| full | prose | `0.8273` | `0.7968` | `0.7486` | `-0.0787` | `[-0.1068, -0.0498]` |
| full | glyph | `0.8281` | `0.8418` | `0.8369` | `+0.0088` | `[-0.0072, +0.0249]` |

Compute control vs polarity control on the balanced slice: `+0.2013`,
CI `[+0.1364, +0.2630]`.

The polarity control is unchanged at `0.5000` canonical on the balanced slice —
no construction artifact was introduced. **Both new systems pay a significant
full-set prose deficit**, and the hard arm's (`-0.0787`) is the largest recorded.

### Construction invariants

Exact-mirror enforced at load and re-checked at enrichment selection; no
synthesis; zero eval overlap; side-swap equivariance architecturally exact. The
evaluation suite is unchanged v4, so no new construction artifact is possible on
the measurement side.

## Reading

The result that matters is not the one the phase was designed to test.
`POLARITY_BALANCED_SCALED_2EPOCH.md` established at **1.5B** that balanced data
and compute had saturated — a second epoch bought nothing on the decisive
metric. That conclusion was carried into the 3B work implicitly: the 3B headline
was run at 2 epochs because 2 epochs was where the 1.5B saturated.

**It does not saturate at 3B.** A third epoch is worth `+0.107` discordant. The
3B scaling curve in compute was never actually explored, and the published
`0.4333` was an under-trained point on it.

Hard-negative enrichment is a second-order effect by comparison: it moves
accuracy *within* the discordant population toward the pure add/delete cases,
at a cost in concordant accuracy, without improving the aggregate.

## Claim boundary

Single seed for the compute control and the enrichment control; two seeds for
the hard arm, and they disagree by `0.0561` on the decisive metric. The pure
add/delete evaluation subpopulation is **28 pairs** — every claim about it,
including the `0.0714` baseline figure that motivated the phase, rests on that
sample, and the seed-to-seed swing (17/28 vs 11/28) is larger than the effect
being claimed.

The seed replication is weaker than it appears: the discordant hard cells are
exhausted (gold=B,net=+ is 75 of 75 available, identical across seeds;
gold=A,net=− overlaps 88%), so a redraw cannot vary the hard discordant pairs.
Overall enrichment Jaccard between seeds is `0.348`, carried almost entirely by
the concordant cells. Generalisation evidence rests instead on the eval pure
pairs being disjoint from training, where `2/28 → 17/28` is transfer to unseen
pairs.

Enrichment uses ×4 oversampling of 300 unique pairs, so the hard arm sees those
pairs 8 times across 2 epochs; memorisation cannot be excluded, only bounded by
the held-out result. One backbone (3B bf16), prose-only training rendering,
length 1024, LoRA r=8. CrossVul rows are training data in every arm.

## Next

1. **Extend the compute curve at 3B** — 4, 6, 8 epochs on the unchanged 2,208-pair
   set. This is now the highest-value open question and it needs no new data.
   The saturation point at 3B is simply unknown.
2. **Seed-replicate the compute control**, which currently rests on one run and
   is carrying the headline.
3. **Mine more discordant pairs**, still the binding constraint: 28 evaluation
   pairs and 75–83 trainable hard pairs per cell is too thin for the questions
   now being asked of them.
4. Hard-negative enrichment is **not** recommended as a default. Revisit only if
   the pure add/delete population is itself the target.

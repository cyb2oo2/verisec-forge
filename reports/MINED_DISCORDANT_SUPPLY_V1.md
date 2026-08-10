# Mined Discordant Supply — three arms, one number, no movement

Configs: `configs/research_polarity_balanced_{mined_v3,decontaminated_v2}_4ep_qwen3b_{seed7,seed123}_v1.json`
Checkpoints: `checkpoints/cls_secure_code_polarity_balanced_{mined_v3,decontaminated_v2}_4ep_qwen3b_{seed7,seed123}_lora_v1`
Predictions: `outputs/secure_code_v4_{mined_v3,decon_v2}_4ep_qwen3b_{seed7,seed123}_predictions_1024.jsonl`
Artifacts: `reports/veripatch_rr_{mined_v3,decon_v2}_seed_replication.json`,
`reports/veripatch_rr_{mined_v3,decon_v2}_{seed7,seed123}_slice.json`,
`reports/veripatch_rr_{mined_v3,decon_v2}_vs_v1_seed7.json`

Evaluated under `docs/PURIFIED_EVALUATION_PROTOCOL.md`. All prior artifacts unchanged.

The balanced design is gated by the smallest `(gold × net-sign)` cell, named as the
binding constraint by every report since `POLARITY_BALANCED_SCALED_2EPOCH.md`. This
phase lifts it, and adds the control that says whether lifting it did anything.

| Arm | pairs | cell | steps | languages | contamination |
| --- | ---: | ---: | ---: | --- | --- |
| **v1** published | 2,208 | 552 | 1,104 | 100% C/C++ | 32 / 36 v4 content twins |
| **v2** decontaminated | 2,164 | 541 | 1,084 | 100% C/C++ | clean |
| **v3** mined | 3,160 | 790 | 1,580 | 69% C/C++ | clean |

3B bf16, 4 epochs, lr 2e-5, length 1024, LoRA r=8, two seeds per arm.

## Verdict

**Nothing moved.** Not decontamination, not `+46%` discordant supply, not `+43%`
optimizer steps.

| balanced Δ, prose | seed 7 | seed 123 | **mean** |
| --- | ---: | ---: | ---: |
| v1 published | `+0.2296` | `+0.2036` | **`+0.2166`** |
| v2 decontaminated | `+0.2082` | `+0.2268` | **`+0.2175`** |
| v3 mined | `+0.2170` | `+0.2165` | **`+0.2167`** |

**The three means agree within `0.0009`.** Decontamination moved the aggregate by
`+0.0009`; mining moved it by `-0.0008`. Both are two orders of magnitude below the
seed spread.

| prose discordant | seed 7 | seed 123 | mean | spread |
| --- | ---: | ---: | ---: | ---: |
| v1 published | `0.6333` | `0.5667` | `0.6000` | `0.0674` |
| v2 decontaminated | `0.5944` | `0.6278` | `0.6111` | `0.0334` |
| v3 mined | `0.6111` | `0.6278` | `0.6195` | `0.0167` |

Discordant means rise monotonically across the arms (`0.6000 → 0.6111 → 0.6195`),
but the total rise of `0.0195` is smaller than v1's own seed spread and the arms'
confidence intervals overlap heavily throughout. **This is not a trend; it is three
draws from the same distribution.**

## What the control settled

The v2 arm exists to separate decontamination from everything else. It changed
three readings that the v3-vs-v1 comparison alone had supported.

### 1. Contamination was not inflating the published numbers

The audit found 32 (seed 7) and 36 (seed 123) content twins of v4 evaluation pairs
in the published training sets, of which only 3 land in the 180 discordant
evaluation pairs — bounding the memorisation bias at `0.0167`.

Seed 7 alone looked alarming: removing the twins dropped discordant accuracy
`0.6333 → 0.5944`, larger than that bound. **Seed 123 resolved it as a low draw.**
The v2 *mean* (`0.6111`) is *above* v1's (`0.6000`), so removing the contamination
did not cost accuracy, and the bias bound holds. Published results are not
contaminated in any way that affects their conclusions.

### 2. The variance story does not survive

An earlier revision of this report noted that v3's seed spread was `4×` tighter
than v1's and that this "matches a prediction" recorded in
`BACKBONE_COMPARISON_MATCHED_COMPUTE_V1.md` — that the seed instability was partly
a small-sample artifact of the 552/cell shortage.

**v2 refutes the mechanism.** It has `541` pairs per cell — *fewer* than v1's `552`
— and its spread (`0.0334`) is half v1's (`0.0674`). Cell size cannot explain a
halving in the direction of *less* data. With two seeds per arm, a two-point range
is a very noisy estimator, and the observed `0.0674 / 0.0334 / 0.0167` ordering is
most simply read as noise. **The supply-stabilises-training hypothesis has lost its
only support and should not be carried forward.**

### 3. The full-set degradation is not the language shift

| full set, prose | seed 7 | seed 123 | mean |
| --- | ---: | ---: | ---: |
| v1 published | `-0.0402` | `-0.0386` | `-0.0394` |
| v2 decontaminated | `-0.0490` | `-0.0434` | `-0.0462` |
| v3 mined | `-0.0466` | `-0.0578` | `-0.0522` |

An earlier revision attributed v3's worse full-set prose accuracy to "shifting 31%
of training away from the evaluated language." **v2 is 100% C/C++ and shows the
same degradation** — worse than v3 on seed 7. A language-shift explanation cannot
account for a deficit that appears just as strongly without the language shift. The
`-0.039` to `-0.058` band is run-to-run variation around one value.

## Full results

| Slice | Family | v1 s7 / s123 | v2 s7 / s123 | v3 s7 / s123 |
| --- | --- | --- | --- | --- |
| balanced | prose | `+0.2305` / `+0.2013` | `+0.2240` / `+0.2338` | `+0.2273` / `+0.1948` |
| balanced | glyph | `+0.0844` / `+0.0909` | `+0.0779` / `+0.0877` | **`+0.0942`** / **`+0.0942`** |
| full | prose | `-0.0402` / `-0.0386` | `-0.0490` / `-0.0434` | `-0.0466` / `-0.0578` |
| full | glyph | `+0.0112` / `+0.0088` (ns) | `+0.0096` / `+0.0104` (ns) | `+0.0112` / `+0.0129` (ns) |

Every balanced-prose figure is significant at `p < 1e-6`; every full-glyph figure
is non-significant in all three arms.

**The one consistent signal is glyph transfer.** v3 beats both other arms on the
balanced glyph slice on *both* seeds (`+0.0942` twice, against `+0.0779`–`+0.0909`),
and its glyph discordant accuracy is `0.2278` on both seeds against v2's
`0.2000`/`0.2278`. It is the only measure where the mined arm separates from the
others seed-wise. It is also a small effect on the rendering nobody trains on, and
`EPOCH_CURVE_3B_V1.md` showed glyph transfer at 3B is non-monotonic in compute, so
`+43%` steps is an unexcluded explanation.

## What the mining actually found

Eleven candidate sources surveyed against the published pool
(`reports/discordant_supply_survey.json`); only one is genuinely new:

| Candidate | new pairs | new discordant | verdict |
| --- | ---: | ---: | --- |
| `crossvul_multilang` | 3,779 | 530 | **usable** — 1 held-out content twin, dropped |
| `mixed_pv_dsc` | 1,307 | 276 | **disqualified** — 1,856 content duplicates of the pool, 213 held-out evaluation pairs |
| 7 × PrimeVul variants | ~40–60 combined | ~40 | overlapping slices of a pool already in use |
| `patcheval_train`, `deltasecommits_v1` | 0 | 0 | fully contained in current sources |

**Same-language discordant supply in this repository is exhausted at 541/cell.**
The only headroom is cross-language, at a cost of 31% of the training distribution:

| | v2 | v3 |
| --- | ---: | ---: |
| C / C++ | 2,164 (100%) | 2,171 (69%) |
| PHP | — | 532 (17%) |
| JavaScript / Python / Java | — | 457 (14%) |

## Claim boundary

Two seeds per arm, one backbone (3B bf16), prose-only training rendering, length
1024, LoRA r=8. The decisive metric rests on **180 discordant evaluation pairs**, so
each arm's mean is over two runs of roughly 107–113 correct out of 180.

**Two seeds cannot resolve differences of the size reported here.** The largest
between-arm difference on the decisive metric is `0.0195`, against seed spreads of
`0.0167`–`0.0674`. Nothing in this report should be read as an ordering of the three
arms. What the report establishes is a *null*: three substantially different
training sets produce the same aggregate.

A null result at n=2 is weak evidence of no effect. An effect smaller than
`~0.05` on discordant accuracy would not be detectable at this sample size, so
"mining does not help" should be read as "mining does not help by an amount this
design could see."

v3 still confounds volume, `+43%` optimizer steps, and language against v2; those
three cannot be separated by this data. Only decontamination is cleanly isolated,
by v2 against v1.

CrossVul rows — including the multilingual ones — are training data, not zero-shot,
for every checkpoint here. The v4 suite contains **8 internal content twins** (1,245
pairs, 1,237 distinct fingerprints), unchanged by this work.

## Next

1. **Stop buying discordant pairs from this data.** Three arms spanning `552 → 790`
   per cell produce one number. Either the metric is not supply-limited in this
   range, or the limit is elsewhere — the ~`0.5` independent-inference degeneracy
   documented in `BACKBONE_SCALE_UP_V1.md` is the more likely binding constraint.
2. **A third seed would settle the spreads** if the variance question is worth
   reopening; on this evidence it is not.
3. **Same-language discordant supply requires new data** — upstream CrossVul or
   PrimeVul releases, or another corpus. Better mining of what is present is
   finished.

## Reproducing

    python scripts/build_prose_native_training_set.py --polarity-balanced --seed 7 \
      --source ... --held-out-suite ... \
      --output data/processed/secure_code_polarity_balanced_train_{decontaminated_v2,mined_v3}.jsonl

    python scripts/audit_training_pool_contamination.py      # verifies 0 leaks, 0 dupes
    python scripts/train_antisymmetric_repair.py --config configs/research_polarity_balanced_decontaminated_v2_4ep_qwen3b_seed7_v1.json
    python scripts/train_antisymmetric_repair.py --config configs/research_polarity_balanced_mined_v3_4ep_qwen3b_seed7_v1.json

Full source and held-out lists are in the build summaries
`reports/secure_code_polarity_balanced_train_{decontaminated_v2,mined_v3}*_summary.json`.

| Run | steps | runtime | final train loss |
| --- | ---: | ---: | ---: |
| v2 seed 7 | 1,084 | `3,746 s` | `0.5402` |
| v2 seed 123 | 1,084 | `3,498 s` | `0.5434` |
| v3 seed 7 | 1,580 | `5,575 s` | `0.5257` |
| v3 seed 123 | 1,580 | `5,069 s` | `0.5020` |

Losses are not comparable across arms: different training sets at different step
counts. They are recorded for reproducibility only.

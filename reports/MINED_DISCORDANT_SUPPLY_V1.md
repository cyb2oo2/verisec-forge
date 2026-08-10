# Mined Discordant Supply — more pairs, same accuracy, less variance

Configs: `configs/research_polarity_balanced_mined_v3_4ep_qwen3b_{seed7,seed123}_v1.json`
Checkpoints: `checkpoints/cls_secure_code_polarity_balanced_mined_v3_4ep_qwen3b_{seed7,seed123}_lora_v1`
Predictions: `outputs/secure_code_v4_mined_v3_4ep_qwen3b_{seed7,seed123}_predictions_1024.jsonl`
Artifacts: `reports/veripatch_rr_mined_v3_{seed_replication,vs_v1_seed7}.json`,
`reports/veripatch_rr_mined_v3_{seed7,seed123}_slice.json`

Evaluated under `docs/PURIFIED_EVALUATION_PROTOCOL.md`. All prior artifacts unchanged.

The balanced design is gated by the smallest `(gold × net-sign)` cell, which every
report since `POLARITY_BALANCED_SCALED_2EPOCH.md` has named as the binding
constraint. This phase lifts it and measures what that buys.

## What the mining actually found

Eleven candidate sources were surveyed against the published pool
(`reports/discordant_supply_survey.json`). Only one is genuinely new:

| Candidate | new pairs | new discordant | verdict |
| --- | ---: | ---: | --- |
| `crossvul_multilang` | 3,779 | 530 | **usable** — 1 held-out content twin, dropped |
| `mixed_pv_dsc` | 1,307 | 276 | **disqualified** — 1,856 content duplicates of the existing pool, 213 held-out evaluation pairs |
| 7 × PrimeVul variants | ~40–60 combined | ~40 | overlapping slices of a pool already in use |
| `patcheval_train`, `deltasecommits_v1` | 0 | 0 | fully contained in current sources |

**Within this repository, same-language discordant supply is exhausted.** The only
headroom is cross-language, and taking it costs distributional purity:

| | v2 (decontaminated) | v3 (mined) |
| --- | ---: | ---: |
| C / C++ | 2,164 (100%) | 2,171 (69%) |
| PHP | — | 532 (17%) |
| JavaScript / Python / Java | — | 457 (14%) |
| binding cell `gold=B,net=+` | 541 | **790** |
| training pairs | 2,164 | **3,160** |

## Verdict

**More discordant supply did not move the decisive metric. It appears to have
stabilised it.**

3B bf16, 4 epochs, lr 2e-5, length 1024, LoRA r=8, two seeds per arm.

| prose discordant | seed 7 | seed 123 | mean | spread |
| --- | ---: | ---: | ---: | ---: |
| v1 published (2,208 pairs, 1,104 steps) | `0.6333` | `0.5667` | `0.6000` | `0.0674` |
| **v3 mined (3,160 pairs, 1,580 steps)** | `0.6111` | `0.6278` | `0.6195` | **`0.0167`** |

| balanced Δ | seed 7 | seed 123 | mean | spread |
| --- | ---: | ---: | ---: | ---: |
| v1 published | `+0.2296` | `+0.2036` | `+0.2166` | `0.0260` |
| **v3 mined** | `+0.2170` | `+0.2165` | **`+0.2167`** | **`0.0005`** |

The balanced-Δ means agree to four decimal places. The discordant mean rises
`+0.0195`, comfortably inside v1's own seed spread. **No accuracy was bought.**

What did change is seed-to-seed agreement: `4×` tighter on discordant accuracy and
`50×` tighter on balanced Δ. That direction matches a specific prediction recorded
in `BACKBONE_COMPARISON_MATCHED_COMPUTE_V1.md`, that the seed instability "is
partly a small-sample artifact of the same shortage."

**This is not established.** Two seeds per arm gives a two-point range, a very
noisy estimator of spread; a `4×` difference between two such ranges is entirely
consistent with chance. It is a prediction that survived one test, not a result.
Resolving it needs ≥3 seeds per arm and is the first question in a while where
extra seeds would buy something real.

## The cost side, which is consistent across seeds

| Slice | Family | v1 s7 | v3 s7 | v1 s123 | v3 s123 |
| --- | --- | ---: | ---: | ---: | ---: |
| balanced | prose | `+0.2305` | `+0.2273` | `+0.2013` | `+0.1948` |
| balanced | glyph | `+0.0844` | `+0.0942` | `+0.0909` | `+0.0942` |
| **full** | **prose** | `-0.0402` | **`-0.0466`** | `-0.0386` | **`-0.0578`** |
| full | glyph | `+0.0112` (ns) | `+0.0112` (ns) | `+0.0088` (ns) | `+0.0129` (ns) |

**Full-set prose accuracy is worse on both seeds** — mean `-0.0522` against v1's
`-0.0394`. Each individual interval overlaps its v1 counterpart, so no single
comparison is significant, but the sign is the same twice and the direction is
what a 31% shift of training away from the evaluated language predicts.

Balanced glyph is nominally better on both seeds (`+0.0942` on each, identical to
four decimals), which is the mirror image: the multilingual pairs help slightly on
the rendering nobody trains on and hurt slightly on the full population of the
language being evaluated.

## What this comparison cannot separate

v3 differs from v1 in **four** ways at once:

1. **Decontamination** — v1 carried 32 (seed 7) and 36 (seed 123) content twins of
   v4 evaluation pairs; v3 carries zero.
2. **Volume** — 2,208 → 3,160 pairs.
3. **Compute** — 1,104 → 1,580 optimizer steps. Unavoidable: the balanced design
   ties set size to the binding cell, so more data means more steps at fixed
   epochs. `EPOCH_CURVE_3B_V1.md` showed compute alone moves this metric
   `0.4326 → 0.7022`, so this is not a minor confound.
4. **Language** — 100% → 69% C/C++.

That a `+43%` step increase produced no gain is itself informative: on the epoch
curve, steps of that order moved the metric substantially. Either the added
cross-language pairs contribute nothing to this metric, or they contribute
something that offsets the compute gain. **This data cannot distinguish those.**

The arm that would separate (1) from (2)–(4) is **v2 at the same 4 epochs**:
decontaminated, C/C++ only, 2,164 pairs, 1,082 steps. It has been built and
verified clean but not trained.

## Claim boundary

Two seeds per arm, one backbone (3B bf16), one training set per seed, prose-only
training rendering, length 1024, LoRA r=8. The decisive metric rests on **180
discordant evaluation pairs** throughout, so `0.6195` is a mean over two runs of
110/180 and 113/180.

Every number here is a comparison against **v1, which is contaminated** — 32 and
36 pairs of v4 evaluation content respectively. The bias that introduces is
bounded at `0.0167` on the decisive metric (3 of 180 discordant pairs have a
training twin), which is smaller than the seed spread but *not* smaller than the
`+0.0195` mean difference this report declines to call a gain. That is a further
reason the v3-vs-v1 comparison should not be read as a measurement of mining.

The v4 evaluation suite itself contains **8 internal content twins** (1,245 pairs,
1,237 distinct content fingerprints), unchanged by this work and unaddressed.

CrossVul rows — now including the multilingual ones — are training data, not
zero-shot, for every checkpoint here.

## Next

1. **Train v2 at 4 epochs, two seeds.** The only arm that isolates decontamination
   from volume, compute and language. Roughly 3 GPU-hours and it makes every
   number above interpretable.
2. **A third seed on v1 and v3** if the variance result matters. It is the one
   open question here that more seeds would settle.
3. **Same-language discordant supply requires new data**, not better mining of what
   is present. Upstream CrossVul/PrimeVul releases or another corpus are the only
   routes to more C/C++ discordant pairs.

## Reproducing

    python scripts/build_prose_native_training_set.py --polarity-balanced --seed 7 \
      --source primevul=... --source patcheval=... --source deltasecommits=... \
      --source crossvul=... \
      --source crossvul_multilang=data/processed/secure_code_crossvul_pair_diff_multilang_eval_metadata.jsonl \
      --held-out-suite ... \
      --output data/processed/secure_code_polarity_balanced_train_mined_v3.jsonl

    python scripts/audit_training_pool_contamination.py     # verifies 0 leaks, 0 dupes
    python scripts/train_antisymmetric_repair.py --config configs/research_polarity_balanced_mined_v3_4ep_qwen3b_seed7_v1.json

The full source and held-out lists are recorded in
`reports/secure_code_polarity_balanced_train_mined_v3_summary.json`.

Training: 1,580 steps each, `5,575 s` (seed 7) and `5,069 s` (seed 123), final
train loss `0.5257` and `0.5020`. Losses are not comparable to v1's, which was a
different training set at a different step count.

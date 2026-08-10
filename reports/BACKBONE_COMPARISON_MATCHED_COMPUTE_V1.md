# Backbone Comparison at Matched Compute — the plateau was compute, the gap is capacity

Configs: `configs/research_polarity_balanced_scaled_4ep_qwen{15b,7b}_{seed7,seed123}_v1.json`
Checkpoints: `checkpoints/cls_secure_code_polarity_balanced_scaled_4ep_qwen{15b,7b}_{seed7,seed123}_lora_v1`
Predictions: `outputs/secure_code_v4_polarity_balanced_scaled_4ep_qwen{15b,7b}_{seed7,seed123}_predictions_1024.jsonl`
Artifacts: `reports/veripatch_rr_4ep_qwen{15b,7b}_seed_replication.json`,
`reports/veripatch_rr_4ep_qwen{15b,7b}_{seed7,seed123}_slice.json`,
`reports/veripatch_rr_4ep_qwen7b_2ep_vs_4ep.json`

The 3B arm is not retrained here; its 4-epoch points come from
`EPOCH_CURVE_3B_V1.md` and its artifact `reports/veripatch_rr_4ep_seed_replication.json`.

One further artifact, `reports/veripatch_rr_4ep_qwen15b_seed7_replication.json`,
compares 4ep seed 7 against the **1-epoch** balanced run and is the source of the
`0.2611` row below. Its `baseline_antisym` therefore means something different
from the same key in `veripatch_rr_4ep_qwen15b_seed_replication.json`, where the
baseline is 4ep seed 7. Check which baseline a file carries before quoting from
it; the `repaired_antisym` block is the 4-epoch checkpoint in both.

Evaluated under `docs/PURIFIED_EVALUATION_PROTOCOL.md`. **All prior artifacts are
unchanged**; every file produced here is written to a new path.

This phase runs the step `BACKBONE_SCALE_UP_V1.md` and `EPOCH_CURVE_3B_V1.md`
both named: retrain the 1.5B and the 7B at the same compute the 3B curve was
measured at, so the backbone comparison is not read off an under-trained point.
Two seeds per backbone, same 2,208-pair balanced set, each backbone's own
prose-native stage-2 init, lr 2e-5, length 1024, LoRA r=8. Only
`num_train_epochs` differs from the published runs.

All three arms were trained and evaluated under the same GPU budget
(`VRF_GPU_MEMORY_FRACTION=0.60`), so the memory regime is not a differentiator
between backbones here.

## Verdict

**Two things were confounded in the original scale-up, and they separate cleanly
once both backbones are trained to 4 epochs.**

1. **The `0.26–0.28` discordant plateau was compute, not capacity.** The 1.5B
   clears it on *both* seeds using nothing but more optimizer steps on data it
   already had. `BACKBONE_SCALE_UP_V1.md` attributed that plateau to the 1.5B's
   capacity; the plateau does not survive training the 1.5B properly.
2. **The capacity gap is real, and larger than that report claimed.** Measured
   where both backbones get the same compute, the 3B beats the 1.5B by `0.20`
   mean discordant accuracy with disjoint bands at two seeds each — against the
   `0.13` asserted at 2 epochs.
3. **The non-monotonicity is not a compute artifact either.** Trained to the same
   4 epochs, the nf4 7B still lands *between* the 1.5B and the 3B on every seed.
   All three bands are disjoint. Whatever costs the 7B its place in the ordering
   survives training it properly.

The original report's *direction* was right on both counts. Its *evidence* was
not, because it compared three under-trained arms and read the differences
between them as capacity.

## The 1.5B compute curve

Population estimator, prose, 1,202 pairs with defined polarity (1,022 concordant
/ 180 discordant). Everything held fixed except epochs.

| 1.5B balanced | concordant | discordant | balanced Δ | 95% CI |
| --- | ---: | ---: | ---: | --- |
| 552/cell × 1ep | `0.8875` | `0.2611` | `+0.0743` | — |
| 552/cell × 2ep (published) | `0.9168` | `0.2833` | `+0.1001` | `[+0.0668, +0.1345]` |
| **4ep, seed 7** | `0.8659` | **`0.4389`** | `+0.1524` | `[+0.1151, +0.1904]` |
| **4ep, seed 123** | `0.9031` | **`0.3611`** | `+0.1321` | `[+0.0956, +0.1682]` |

The worst 4-epoch seed sits `+0.0778` above `0.2833`, the best the 1.5B had
reached on any run that preserved its decision. The 1.5B was not at a ceiling; it
was under-trained, exactly as the 3B was.

(INLP reached a higher `0.5056` at 1.5B, but only by destroying the decision —
concordant accuracy collapsed to `0.6037`, and `BACKBONE_SCALE_UP_V1.md` set that
as the discriminating test for a dilution artifact — a decision drifting toward
random raises discordant accuracy while the balanced Δ stays flat. The runs here
pass that test: concordant accuracy holds at `0.8659`/`0.9031` and the balanced Δ
*rises*, `+0.1001` → `+0.1321`/`+0.1524`.)

## Matched compute: all three backbones at 4 epochs

Two seeds per backbone, identical recipe, identical evaluator, same 1,104
optimizer steps on the same 2,208 pairs.

| discordant, prose | precision | seed 7 | seed 123 | mean | band |
| --- | --- | ---: | ---: | ---: | --- |
| 1.5B @ 4ep | bf16 | `0.4389` | `0.3611` | `0.4000` | `0.3611–0.4389` |
| **7B @ 4ep** | nf4 | `0.5167` | `0.5167` | **`0.5167`** | `0.5167` |
| **3B @ 4ep** | bf16 | **`0.6333`** | **`0.5667`** | **`0.6000`** | `0.5667–0.6333` |

| balanced Δ, prose | seed 7 | seed 123 | mean |
| --- | ---: | ---: | ---: |
| 1.5B @ 4ep | `+0.1524` | `+0.1321` | `+0.1423` |
| 7B @ 4ep | `+0.1864` | `+0.1810` | `+0.1837` |
| **3B @ 4ep** | **`+0.2296`** | **`+0.2036`** | **`+0.2166`** |

**All three bands are disjoint on the decisive metric**, and the ordering
`1.5B < 7B < 3B` holds on every seed. The worst 3B seed beats the 7B by `0.0500`
and the best 1.5B seed by `0.1278`. This is the best-powered backbone comparison
in the project: two seeds per arm, at equal compute, on identical data.

The `0.20` mean gap between the 1.5B and the 3B is the capacity result. The 7B's
position between them is a separate question, treated below.

### What happens to the original disjointness argument

`BACKBONE_SCALE_UP_V1.md` argued: "Four 1.5B runs span `0.2611–0.2833`; two 3B
seeds span `0.4167–0.4333`. There is no overlap and a `0.13` gap between them."

That comparison is between a 1.5B at 2 epochs and a 3B at 2 epochs. Trained to 4
epochs, the 1.5B reaches `0.4389`, which **overlaps and exceeds the entire 3B
2-epoch band**. The bands are disjoint only at equal compute; at unequal compute
they cross. The `0.13` figure should not be quoted as a capacity gap — the
matched-compute gap is `0.20`.

## The 7B: compute moves it, and does not move its rank

The within-7B comparison is the one statement this arm can make without the nf4
confound, because both points are the same quantized backbone
(`reports/veripatch_rr_4ep_qwen7b_2ep_vs_4ep.json`).

| 7B nf4, prose | concordant | discordant | balanced Δ | 95% CI |
| --- | ---: | ---: | ---: | --- |
| 2ep (published) | `0.8845` | `0.3833` | `+0.1339` | `[+0.0971, +0.1712]` |
| **4ep, seed 7** | `0.8562` | **`0.5167`** | `+0.1864` | `[+0.1479, +0.2242]` |
| **4ep, seed 123** | `0.8454` | **`0.5167`** | `+0.1810` | `[+0.1422, +0.2193]` |

The 2-epoch row reproduces `BACKBONE_SCALE_UP_V1.md` exactly, one of three
bit-for-bit evaluator checks performed in this phase (the others being the 1.5B
2-epoch point at `0.9168`/`0.2833`/`+0.1001` and the 3B 2-epoch point).

**Compute moves the 7B as much as it moves the others** (`+0.1334` discordant,
2→4 epochs) **but does not change where it ranks.** `BACKBONE_SCALE_UP_V1.md`
offered two readings of the 7B dip — quantization cost, or a genuine plateau past
3B — and noted the data could not separate them. Matched compute does not
separate them either; it only removes under-training as a third candidate.

### The transfer result inverts the ordering

On the glyph rendering, which the balanced stage never trains on, the 7B is the
**strongest** arm, on both seeds:

| Glyph, 4ep | 1.5B s7 / s123 | 7B s7 / s123 | 3B s7 / s123 |
| --- | --- | --- | --- |
| discordant | `0.1833` / `0.1833` | **`0.2556`** / **`0.2556`** | `0.2167` / `0.2278` |
| balanced Δ (population) | `+0.0540` / `+0.0579` | **`+0.1116`** / **`+0.1082`** | `+0.0893` / `+0.0933` |
| balanced slice Δ | `+0.0422` / `+0.0455` | **`+0.1071`** / **`+0.0942`** | `+0.0844`¹ |
| full set Δ | `-0.0265` / `-0.0177` | **`+0.0249`** / **`+0.0193`** | `+0.0112`¹ (ns) |

¹ 3B slice and full-set figures are seed 7 only — no seed-123 slice artifact was
produced for the 3B in `EPOCH_CURVE_3B_V1.md`. Its population figures above are
seed-replicated.

**The 7B is the only arm whose full-set glyph delta is significantly positive**,
and it replicates across seeds (`p=0.0032`, `p=0.029`). The 1.5B is significantly
*negative* on the same measure. So the backbone that ranks second on the trained
rendering ranks first on the untrained one.

This is hard to reconcile with uniform quantization damage, which should cost the
7B everywhere rather than only on the objective it was trained against. A reading
consistent with all of it — and not established by it — is that nf4 costs
precision on the fitted prose decision while the extra capacity still buys
generalization off it. **Separating that from a genuine plateau past 3B still
requires a bf16 7B**, which does not fit a 12 GB card. Nothing in this phase
changes that.

## The cost side, which grew

Balanced slice (308 pairs) and full clean set (1,245 pairs), both-directions
correct, against the semantics-free control.

| Slice | Family | control | 1.5B 4ep seed 7 | 1.5B 4ep seed 123 |
| --- | --- | ---: | --- | --- |
| balanced | prose | `0.4968` | `0.6526` → `+0.1558` `[+0.0974, +0.2143]` p=`5.35e-07` | `0.6266` → `+0.1299` `[+0.0779, +0.1818]` p=`4.71e-06` |
| balanced | glyph | `0.5000` | `0.5422` → `+0.0422` `[+0.0000, +0.0844]` p=`0.079` | `0.5455` → `+0.0455` `[+0.0032, +0.0877]` p=`0.049` |
| full | prose | `0.8273` | `0.7888` → **`-0.0386`** `[-0.0627, -0.0145]` p=`0.0022` | `0.8088` → `-0.0185` `[-0.0394, +0.0024]` p=`0.104` |
| full | glyph | `0.8281` | `0.8016` → `-0.0265` `[-0.0442, -0.0088]` p=`0.0043` | `0.8104` → `-0.0177` `[-0.0353, +0.0000]` p=`0.061` |

Three things here that should travel with the headline:

- **The full-set prose deficit roughly doubles** against the published 2-epoch
  1.5B (`-0.0209`, significant). The balanced-slice gain is bought on the full
  population's accuracy, the same trade the 3B curve documented.
- **The 1.5B now degrades on glyph too**, which the 3B did not — the 3B's
  full-set glyph delta stayed nominally positive at both points where it was
  measured (`+0.0112` at 4ep, `+0.0072` at 8ep). Off the trained rendering, extra
  compute costs the small backbone something it appears not to cost the large one.
- **The full-set penalty is itself seed-dependent** — significant on seed 7, not
  on seed 123. Balanced-slice glyph transfer straddles significance in the same
  way (`p=0.079` / `p=0.049`). Neither should be reported as an established sign
  on one seed.

The 7B pays a comparable prose cost and, unlike either bf16 arm, is *paid* on
glyph:

| 7B nf4, 4ep | seed 7 | seed 123 |
| --- | --- | --- |
| balanced, prose | `0.6883` → `+0.1916` `[+0.1299, +0.2532]` p=`4.07e-09` | `0.6851` → `+0.1883` `[+0.1266, +0.2468]` p=`4.34e-09` |
| balanced, glyph | `0.6071` → `+0.1071` `[+0.0649, +0.1494]` p=`1.96e-06` | `0.5942` → `+0.0942` `[+0.0487, +0.1396]` p=`8.17e-05` |
| full, prose | `0.7968` → `-0.0305` `[-0.0554, -0.0056]` p=`0.0216` | `0.7847` → `-0.0426` `[-0.0691, -0.0169]` p=`0.00142` |
| full, glyph | `0.8530` → **`+0.0249`** `[+0.0088, +0.0410]` p=`0.00322` | `0.8474` → **`+0.0193`** `[+0.0032, +0.0353]` p=`0.0293` |

Full-set prose deficits at 4 epochs are within a narrow band across all three
backbones — `-0.0185`/`-0.0386` (1.5B), `-0.0305`/`-0.0426` (7B), `-0.0402` (3B
seed 7). **The prose cost of 4-epoch balanced training is roughly scale-invariant;
what scales is what you get for it.**

## Seed instability is now the largest recorded

| Metric | seed 7 | seed 123 | spread |
| --- | ---: | ---: | ---: |
| concordant | `0.8659` | `0.9031` | `0.0372` |
| **discordant** | `0.4389` | `0.3611` | **`0.0778`** |
| balanced Δ | `+0.1524` | `+0.1321` | `0.0203` |
| glyph discordant | `0.1833` | `0.1833` | `0.0000` |

`0.0778` exceeds every prior spread in this repository — `0.0166` (3B scale-up),
`0.0561` (hard-negative arm), `0.0674` (3B 4-epoch curve). The instability that
caused the 3B knee to be withdrawn is present at 1.5B and slightly worse.

**The 7B is the opposite case, and its numbers required verification.** Its two
seeds return *identical* discordant accuracy on both renderings — `0.5167` prose
(93/180) and `0.2556` glyph (46/180) — while concordant accuracy differs
(`0.8562` vs `0.8454`). `BACKBONE_SCALE_UP_V1.md` records a previous collision of
this kind at 3B, so the prediction files were checked directly:

| Check | Result |
| --- | --- |
| SHA-256 of the two prediction files | differ |
| rows identical on side and both probabilities | **3 of 4,980** |
| hard-label disagreements | **698 of 4,980** |
| mean absolute difference in `probability_a` | `0.1230` |

These are substantively different models whose counts happen to net to the same
totals on a 180-pair slice. It is a coincidence, not a duplicated file or a
mis-pointed config. **A `0.0000` spread on 180 pairs is itself partly luck** and
should not be read as "the 7B is inherently stable"; the non-zero concordant and
balanced-Δ spreads are the more honest indication of its run-to-run variation.

The two seeds land at different points on the same concordant/discordant trade
(`0.8659`/`0.4389` vs `0.9031`/`0.3611`) — the same pattern `EPOCH_CURVE_3B_V1.md`
observed at 3B, where the seed determined position along the trade more than
overall quality. Here that reading is weaker: the 1.5B seeds also differ on
full-set prose (`0.7888` vs `0.8088`), where the 3B seeds were nearly identical.

## What this corrects

`BACKBONE_SCALE_UP_V1.md`, headline: "The `0.26–0.28` discordant plateau was a
capacity limit of the 1.5B backbone. It is not a property of the task or the data
under the purified protocol."

The second sentence stands. **The first is withdrawn.** The plateau was a
property of the training budget, not of the backbone: the same 1.5B, the same
data, the same recipe, twice the epochs, reaches `0.3611–0.4389`. That report
established that the plateau was not intrinsic to the task — swapping the
backbone did break it. What it could not see, having varied only the backbone, is
that holding the backbone fixed and varying compute breaks it too.

Its supporting arguments degrade accordingly:

- The disjoint-bands argument is void at unequal compute (above).
- "Capacity alone is not the mechanism … the gain appears only where extra
  capacity and the shortcut-free gradient meet" — the mechanism claim needs
  restating. The gain appears where the shortcut-free gradient meets **enough
  optimizer steps**; capacity raises the level it reaches, it is not required to
  reach it.

Everything in that report that does not rest on the capacity attribution is
unaffected, including its tokenizer-identity check, its upstream S0/S1
comparisons, its INLP-dilution discrimination, its contamination analysis, and
every 1.5B and 3B measurement it publishes. This report supersedes it **only** on
the cause of the 1.5B plateau and on the size of the backbone gap.

It also confirms `EPOCH_CURVE_3B_V1.md`'s suspicion, stated there as a caveat:
"every point here was trained at 2 epochs, which the later compute curve shows is
under-trained for the 3B." It was under-trained for the 1.5B as well. Going from
2 to 4 epochs moves mean discordant accuracy by `+0.1167` at 1.5B
(`0.2833` → `0.4000`) and `+0.1750` at 3B (`0.4250` → `0.6000`) — so the larger
backbone converts the extra compute into more accuracy, not less. Under-training
cost both arms, and cost the 3B arm more in absolute terms.

## A derivation note that affects quoted numbers

The 3B 4-epoch figures here (`0.6333` / `0.5667`) come from
`reports/veripatch_rr_4ep_seed_replication.json`, the evaluator artifact, which
computes discordant accuracy over **180** pairs. `EPOCH_CURVE_3B_V1.md` prints
`0.6292` / `0.5618` for the same checkpoints, from the independent recomputation
described in `BACKBONE_SCALE_UP_V1.md` §"Independently recomputed", which derives
net polarity differently and admits **178** pairs.

Both derivations are in the repository and neither is wrong; they differ by two
pairs. **All cross-backbone comparisons in this report use the evaluator
derivation on both sides**, so the tables above are like-for-like. Mixing the two
derivations across a comparison would introduce a spurious `~0.004`.

## Claim boundary

Two seeds per backbone at 4 epochs. Seed spreads on the decisive metric are
`0.0778` (1.5B), `0.0674` (3B) and `0.0000` (7B, a coincidence — see above), so
**a two-seed mean is a weak estimate** for the bf16 arms. The `0.20` 1.5B-vs-3B
gap survives that easily and the `0.05` 7B-vs-3B gap does not survive it as
comfortably: it is smaller than the 3B's own seed spread, and rests on the 7B
band being a point estimate rather than a measured range. **The three-way
ordering is established; the size of the 7B-to-3B step is not.**

No smaller difference in this report should be treated as resolved. In
particular, the 1.5B's `+0.1423` mean balanced Δ against the 3B's 2-epoch
`+0.1614`/`+0.1629` is *not* a resolved ordering.

The decisive metric rests on **180 discordant evaluation pairs** throughout, so
`0.4389` is 79/180 and its sampling error is not small. CrossVul rows are
training data for every checkpoint compared here. One model family
(Qwen2.5-Coder), prose-only training rendering, length 1024, LoRA r=8 — a rank
the 3B may under-use, which remains an untested alternative explanation for part
of the backbone gap.

**The 7B arm is nf4 throughout** — training, inference and probing — as it was in
`BACKBONE_SCALE_UP_V1.md`. The within-7B 2ep→4ep comparison is clean; every
cross-backbone statement involving the 7B carries that confound permanently, and
no amount of matched compute removes it. Its rank between the 1.5B and the 3B is
therefore a measurement of *this quantized system*, not of 7B-scale capacity.

The 3B arm was not retrained in this phase. Its 4-epoch numbers are the ones
published in `EPOCH_CURVE_3B_V1.md`, re-read from the same evaluator artifact for
like-for-like comparison; its slice and full-set figures exist for seed 7 only.

Discordant accuracy at 1.5B remains **below the `0.5` chance line on both seeds**.
The model is still wrong on the majority of pairs where polarity misleads. This is
a large movement on a previously immovable metric, not a demonstration of
relational competence.

## Next

1. ~~7B at 4 epochs, both seeds~~ — **done**; see above. The non-monotonicity
   survived, so the open question is now narrower and hardware-bound: **a bf16 (or
   8-bit) 7B on a card with more than 12 GB**, which is the only thing that can
   separate quantization cost from a genuine plateau past 3B. The transfer
   inversion documented here makes that test more interesting than it was, not
   less — uniform quantization damage does not predict it.
2. **Mine more discordant pairs.** Unchanged from both prior reports and now
   binding on three separate things at once: the 180-pair decisive metric, the
   552/cell training ceiling, and the seed instability documented above — which
   is partly a small-sample artifact of the same shortage.
3. **Resolving any epoch-to-epoch ordering needs ≥3 seeds per point.** Given
   spreads near `0.08`, this is only worth doing if a stopping rule matters
   operationally; neither the compute effect nor the capacity gap needs it.

## Reproducing

    # 1.5B and 7B at 4 epochs, both seeds
    python scripts/train_antisymmetric_repair.py --config configs/research_polarity_balanced_scaled_4ep_qwen15b_seed7_v1.json
    python scripts/train_antisymmetric_repair.py --config configs/research_polarity_balanced_scaled_4ep_qwen15b_seed123_v1.json
    python scripts/train_antisymmetric_repair.py --config configs/research_polarity_balanced_scaled_4ep_qwen7b_seed7_v1.json
    python scripts/train_antisymmetric_repair.py --config configs/research_polarity_balanced_scaled_4ep_qwen7b_seed123_v1.json

    # 7B inference additionally needs --load-in-4bit, since inference precision
    # is part of the reported system and must match how the adapter was trained

    # inference (batch 4; batch 8 exhausts a 12 GB card on the length-1024 tails)
    python scripts/predict_veripatch_rr.py \
      --checkpoint checkpoints/cls_secure_code_polarity_balanced_scaled_4ep_qwen15b_seed7_lora_v1 \
      --dataset data/processed/secure_code_relational_benchmark_v4_runtime1024.jsonl \
      --output outputs/secure_code_v4_polarity_balanced_scaled_4ep_qwen15b_seed7_predictions_1024.jsonl \
      --batch-size 4 --resume

    # seed-vs-seed replication and the slice/full-set control
    python scripts/replicate_balanced_slice_gain.py \
      --baseline-predictions outputs/secure_code_v4_polarity_balanced_scaled_4ep_qwen15b_seed7_predictions_1024.jsonl \
      --repaired-predictions outputs/secure_code_v4_polarity_balanced_scaled_4ep_qwen15b_seed123_predictions_1024.jsonl \
      --output reports/veripatch_rr_4ep_qwen15b_seed_replication.json
    python scripts/evaluate_balanced_slice_control.py \
      --baseline-predictions outputs/secure_code_v4_prose_native_pilot_predictions_1024.jsonl \
      --repaired-predictions outputs/secure_code_v4_polarity_balanced_scaled_4ep_qwen15b_seed7_predictions_1024.jsonl \
      --output reports/veripatch_rr_4ep_qwen15b_seed7_slice.json

All four training runs and all inference here were executed with the GPU budget
set, since the card also drives the display:

    VRF_GPU_MEMORY_FRACTION=0.60 VRF_GPU_THROTTLE_MS=30 python scripts/...

The nf4 7B trains and runs inference inside the same `7.2 GiB` cap as the smaller
bf16 arms, so the budget is not a source of asymmetry between backbones.

| Run | steps | runtime | final train loss |
| --- | ---: | ---: | ---: |
| 1.5B seed 7 | 1,104 | `4,927 s` | `0.6179` |
| 1.5B seed 123 | 1,104 | `4,782 s` | `0.6273` |
| 7B seed 7 | 1,104 | `5,996 s` | `0.5351` |
| 7B seed 123 | 1,104 | `8,197 s`¹ | `0.5264` |

¹ Wall-clock only; two CPU-bound evaluations were running concurrently. It is not
a per-step cost difference and carries no interpretation.

Training losses are **not** comparable across backbones — the 7B's lower loss
(`0.53`) against the 1.5B's (`0.62`) sits alongside a *worse* discordant accuracy
than the 3B, and `BACKBONE_SCALE_UP_V1.md` used the 7B's higher 2-epoch loss as
one signal of quantization damage. Loss is reported here for reproducibility, not
as evidence.

Status files:
`reports/repair_train_status_polarity_balanced_scaled_4ep_qwen{15b,7b}_{seed7,seed123}_v1.json`.

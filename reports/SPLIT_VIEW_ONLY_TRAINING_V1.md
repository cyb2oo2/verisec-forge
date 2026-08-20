# Split-View-Only Training (Arc 2 Q1)

Artifact: `reports/veripatch_rr_split_view_only_training.json`
Script: `scripts/analyze_split_view_only_training.py`
Protocol: `docs/SPLIT_VIEW_ONLY_TRAINING_PROTOCOL.md`
Config: `configs/research_split_view_only_qwen3b_v1.json`
Suite: `data/processed/secure_code_relational_benchmark_v4_runtime1024.jsonl` (admissible `v4`)
Checkpoint: `checkpoints/cls_secure_code_split_view_only_qwen3b_lora_v1`

**This does not revive the locked antisymmetric epoch-curve claims.** It is one from-scratch 3B run on `split_view` only. `stop_training = true` for the old glyph-exposed curve is unchanged.

## Pre-registered protocol (written before the run)

- Budget: `4` epochs, `1104` optimizer steps, seed 7, 2,208 polarity-balanced pairs.
- Init: base `Qwen/Qwen2.5-Coder-3B-Instruct` + fresh LoRA. No polarity-balanced, prose-native, or joint-pairwise checkpoint.
- Rendering: `split_view` only. Glyph layout forbidden in the trainer.
- Primary cell: prose / polarity-balanced / ALL (n=308).
- Published prose-control comparator: `0.8433` (Arc 2). v4 char-net on this suite: `0.8502` full, `0.5000` balanced.
- Failure: balanced independent Wilson includes `0.5`, **or** full-set independent does not exceed the v4 control.
- Unexpected positive: both failure arms escaped. Not a method win.
- Do not add epochs, seeds, or mined pairs.

### Adjudication criterion — Amendment A (2026-08-18, **post-run**)

The pre-registered phrase *"both-directions-correct also leaves chance"* fixed no numeric null. The operationalization below was written **after** the run and is **not** part of the exact pre-registered numerical rule. It does not change this run's outcome. See `docs/SPLIT_VIEW_ONLY_TRAINING_PROTOCOL.md`, Amendment A.

Unexpected positive requires **all** of:

| Requirement | Level | Uncertainty |
| --- | --- | --- |
| Balanced canonical accuracy | `> 0.5` | Wilson 95% lower bound `> 0.5` |
| Balanced swap accuracy | `> 0.5` | Wilson 95% lower bound `> 0.5` |
| Full-set independent accuracy | `> 0.8502` | locked control |

Gating on joint both-correct against a fixed constant is *not* the estimand: the uncoupled baseline is `p_canonical * p_swap`, which equals `0.25` only when both marginals are exactly `0.5`. Canonical `0.80` with swap `0.40` and both-correct `0.32` would clear a fixed `0.25` while the swap decision sits *below* chance with no coupling beyond the marginals.

## Train status and provenance

Validated against the pre-declared budget before any verdict is issued. A missing or mismatched field forces `indeterminate`. All checks pass: `True`.

| Field | Observed | Expected | ok |
| --- | ---: | ---: | ---: |
| `config.require_split_view_only` | `True` | `True` | `True` |
| `config.seed` | `7` | `7` | `True` |
| `config.num_train_epochs` | `4` | `4` | `True` |
| `config.predeclared_steps` | `1104` | `1104` | `True` |
| `config.training_pairs` | `2208` | `2208` | `True` |
| `config.model_name` | `Qwen/Qwen2.5-Coder-3B-Instruct` | `Qwen/Qwen2.5-Coder-3B-Instruct` | `True` |
| `config.output_dir` | `checkpoints/cls_secure_code_split_view_only_qwen3b_lora_v1` | `checkpoints/cls_secure_code_split_view_only_qwen3b_lora_v1` | `True` |
| `config.init_checkpoint_absent` | `None` | `<key absent>` | `True` |
| `status.status` | `ok` | `ok` | `True` |
| `status.smoke` | `False` | `False` | `True` |
| `status.seed` | `7` | `7` | `True` |
| `status.train_pairs` | `2208` | `2208` | `True` |
| `status.steps_per_epoch` | `276` | `276` | `True` |
| `status.model_name` | `Qwen/Qwen2.5-Coder-3B-Instruct` | `Qwen/Qwen2.5-Coder-3B-Instruct` | `True` |
| `status.output_dir` | `checkpoints/cls_secure_code_split_view_only_qwen3b_lora_v1` | `checkpoints/cls_secure_code_split_view_only_qwen3b_lora_v1` | `True` |
| `status.init_checkpoint` | `None` | `None` | `True` |
| `status.epochs` | `4.0` | `4` | `True` |
| `status.total_optimizer_steps` | `1104` | `1104` | `True` |

### Prediction artifact binding

The evaluated predictions are bound to the validated run before any verdict is issued. All checks pass: `True`.

- prediction rows: `4980`, unique ids: `4980`
- model_id(s): `['checkpoints/cls_secure_code_split_view_only_qwen3b_lora_v1']`
- normalized model_id: `checkpoints/cls_secure_code_split_view_only_qwen3b_lora_v1` — checkpoint: `checkpoints/cls_secure_code_split_view_only_qwen3b_lora_v1` — expected output dir: `checkpoints/cls_secure_code_split_view_only_qwen3b_lora_v1`
- required suite renderings: `4980`, absent: `0`, malformed probabilities: `0`

| Family | expected full | resolved full | expected balanced | resolved balanced | pairs missing predictions |
| --- | ---: | ---: | ---: | ---: | ---: |
| glyph | 1202 | 1202 | 308 | 308 | 0 |
| prose | 1202 | 1202 | 308 | 308 | 0 |

Expected counts are derived from the loaded admissible suite, not hard-coded.

### Reproducibility binding

- git commit: `79b0cd4327b8c9c648746e379c3849e6bc496058`
- working tree dirty: `True` (`weakened_dirty_tree`)
- checkpoint identity: `checkpoints/cls_secure_code_split_view_only_qwen3b_lora_v1` (model `Qwen/Qwen2.5-Coder-3B-Instruct`); checkpoint weights are local and deliberately not hashed
- **publication_ready: `False`**

| Role | Path | SHA256 (LF-normalized) | bytes | tracked | gitignored |
| --- | --- | --- | ---: | ---: | ---: |
| config | `configs/research_split_view_only_qwen3b_v1.json` | `61b7db2fdd855ad2…` | 1745 | `True` | `False` |
| train_status | `reports/repair_train_status_split_view_only_qwen3b_v1.json` | `7f6dfe1986beb4c4…` | 309 | `True` | `False` |
| suite | `data/processed/secure_code_relational_benchmark_v4_runtime1024.jsonl` | `c8ea99b894623f3d…` | 19178616 | `False` | `True` |
| suite_summary | `reports/secure_code_relational_benchmark_v4_summary.json` | `9861d5404daf6d2e…` | 3866 | `True` | `False` |
| predictions | `outputs/secure_code_v4_split_view_only_qwen3b_predictions_1024.jsonl` | `3c869a6bc84d633a…` | 1586712 | `False` | `True` |

**Publication readiness is `false`.** Gitignored inputs: `['predictions', 'suite']`; missing inputs: `[]`. The manifest binds these by content hash, but they are not in committed history, so their provenance cannot be reconstructed from the repository alone. This is reported rather than papered over.

## Verdict

ceiling_holds: the run did not meet the adjudication criterion for a usable independent decision, and its full-set independent point estimate did not approach the locked 0.8502 reference. This is an adjudication label, not proof that all relational information is absent. stop_training stays true.

**Primary outcome: `ceiling_holds`.** The three states are adjudicated explicitly and are mutually exclusive.

| State | Value |
| --- | ---: |
| indeterminate | `False` |
| unexpected_positive | `False` |
| ceiling_holds | `True` |

Adjudicated inputs:

- balanced canonical clears `0.5` from above: `False`
- balanced swap clears `0.5` from above: `False`
- full-set independent **point estimate** exceeds the locked `0.8502` reference: `False` (point-estimate gate, not a paired superiority test)
- provenance matches the pre-declared budget: `True`
- prediction artifact is bound to the validated run: `True`
- balanced slice satisfies `both_correct = (canonical + swap - frozen)/2`: `True` (residual `5e-05`)
- stop_training: `True`

Secondary mechanistic flag — degeneracy_reappears: `False` (threshold `|antisym - independent| >= 0.1` on prose/full/discordant; observed delta `0.0389`). Secondary descriptive operationalization: fires when |antisym_accuracy - independent_canonical_accuracy| on the full discordant cell is >= 0.1 while that cell's independent Wilson interval still includes 0.5. The 0.1 threshold is descriptive and is NOT part of the primary pre-registered success/failure adjudication. It is recorded alongside the primary outcome and never replaces or modifies it.

## Strongest semantics-free control

Rule: `char_net_sign` — predict A iff glyph char_net > 0, else B; zero-net dropped.

| Slice | n | control accuracy |
| --- | ---: | ---: |
| full (nonzero-net) | 1202 | `0.8502` |
| polarity-balanced | 308 | `0.5000` |

On any polarity-balanced slice the four (gold x net-sign) cells are equalised, so this control is exactly 0.5 by construction.

Locked Arc 2 prose control on the 600-pair `split_view` measurement: `0.8433`. That number is not recomputed here.

## Exact-mirror rejection (suite construction)

Invariant: swap_mirror_is_exact enforced at load; non-mirror pairs rejected.

| Source | pairs seen | rejected non-mirror | rate | sampled |
| --- | ---: | ---: | ---: | ---: |
| primevul | 827 | 30 | `0.0363` | 350 |
| deltasecommits | 327 | 11 | `0.0336` | 316 |
| patcheval | 269 | 40 | `0.1487` | 229 |
| crossvul | 4371 | 153 | `0.0350` | 350 |

## Primary — prose / polarity-balanced (train-matched split_view)

Char-net and the prose header rule are `0.50` on this slice. Independent is the 0.5-threshold per-rendering decision. Antisym is the pair-level projection, reported only as the secondary degeneracy check.

Chance is `0.50` for both per-rendering decisions. The adjudication gate is canonical **and** swap, each clearing `0.50` from above. Both-correct is a diagnostic column, not a gate: `0.25` is the absolute baseline for two independent 50/50 random decisions and nothing more — the uncoupled baseline is `p_canonical * p_swap`, and `both_correct <= 1 - frozen` caps the column outright.

| Cell | n | indep canonical (Wilson) | indep swap (Wilson) | both-correct (Wilson) | antisym | frozen | control |
| --- | ---: | --- | --- | --- | ---: | ---: | ---: |
| ALL | 308 | `0.5487` [`0.4929`, `0.6033`] | `0.5325` [`0.4767`, `0.5874`] | `0.1201` [`0.0884`, `0.1612`] | `0.6071` | `0.8409` | `0.5000` |
| discordant | 154 | `0.4675` [`0.3905`, `0.5462`] | `0.4935` [`0.4157`, `0.5717`] | `0.0260` [`0.0101`, `0.0649`] | `0.4221` | `0.9091` | `0.0000` |

### Exact counts (balanced / ALL)

| Quantity | Count |
| --- | ---: |
| pairs | 308 |
| frozen | 259 |
| unfrozen | 49 |
| canonical correct | 169 |
| swap correct | 164 |
| both correct | 37 |
| both correct, unfrozen | 37 |

### Secondary diagnostics (post-hoc, descriptive)

Neither feeds the verdict.

**Both-correct among unfrozen pairs** — computed from the integer counts above, not from rounded rates: `37`/`49` = `0.7551`, Wilson 95% `0.7551` [`0.6191`, `0.8540`], covering `0.1591` of the slice. Conditioning on 'not frozen' was chosen after seeing the frozen share, so this is descriptive only. On unfrozen pairs `canonical_correct == swap_correct` holds identically, so it equals independent canonical accuracy there.

**Coupling** — observed both-correct `0.1201` against the marginal-conditioned baseline `p_canonical * p_swap` = `0.2922` (excess `-0.1721`, attainable cap `1 - frozen` = `0.1591`). No inference is drawn: a claim here would need a pre-specified paired bootstrap or permutation over pairs, which this analysis does not perform.

## Prose / full set (train-matched split_view)

| Cell | n | indep canonical (Wilson) | antisym (Wilson) | frozen | control |
| --- | ---: | --- | --- | ---: | ---: |
| ALL | 1202 | `0.5674` [`0.5392`, `0.5951`] | `0.7712` [`0.7466`, `0.7941`] | `0.8261` | `0.8502` |
| concordant | 1022 | `0.5832` [`0.5527`, `0.6130`] | `0.8297` [`0.8055`, `0.8515`] | `0.8160` | `1.0000` |
| discordant | 180 | `0.4778` [`0.4060`, `0.5504`] | `0.4389` [`0.3684`, `0.5119`] | `0.8833` | `0.0000` |

## Glyph family (reference only — never trained on)

| Cell | n | indep canonical | antisym | frozen | control |
| --- | ---: | ---: | ---: | ---: | ---: |
| balanced ALL | 308 | `0.5162` | `0.5812` | `0.9643` | `0.5000` |
| full ALL | 1202 | `0.5033` | `0.5258` | `0.9709` | `0.8502` |
| full discordant | 180 | `0.5389` | `0.5722` | `0.9667` | `0.0000` |

## Mechanistic reading

The run did not meet the adjudication criterion for a usable independent decision, and its full-set independent point estimate did not approach the locked reference. On the train-matched prose rendering the balanced slice gives canonical `0.5487` and swap `0.5325`, neither clearing `0.5` from above, and full-set independent `0.5674` is far below the v4 char-net reference `0.8502` and the locked prose reference `0.8433` — a point-estimate comparison, not a paired superiority test. Starting from a fresh LoRA with no glyph exposure therefore did not yield a single-pass decision this protocol would accept. That is an adjudication outcome, not proof that the model holds no relational information — failing to reject chance is not evidence of absence, and the post-hoc unfrozen-subset diagnostic is descriptive and does not reopen training.

## What this does and does not claim

- **One seed, one backbone**, the pre-declared 1,104 steps. No further training was run and none is authorised.
- Not a method win for pair-coupled decoding or a new training recipe.
- Not a continuation of the locked 2/3/4/6/8-epoch curve.
- Not a replacement for the locked `split_view` collapse (`0.5133` / `0.4850` vs prose control `0.8433`).
- **No transfer claim.** CrossVul rows in the v4 *evaluation* suite were held out of this training set's construction keys; CrossVul pairs that are not those keys may still appear in the 2,208-pair train pool, as in the locked polarity-balanced set.
- **`ceiling_holds` is an adjudication label, not proof that all relational information is absent.** Failing to reject chance is not evidence of no signal. The run did not meet the criterion; that is the whole of what is claimed.
- The unfrozen-subset diagnostic is post-hoc and descriptive. It does not reopen training.

## Reproducing

```
python scripts/train_antisymmetric_repair.py \
  --config configs/research_split_view_only_qwen3b_v1.json
python scripts/predict_veripatch_rr.py \
  --checkpoint checkpoints/cls_secure_code_split_view_only_qwen3b_lora_v1 \
  --dataset data/processed/secure_code_relational_benchmark_v4_runtime1024.jsonl \
  --output outputs/secure_code_v4_split_view_only_qwen3b_predictions_1024.jsonl \
  --batch-size 4 --resume --num-labels 2
python scripts/analyze_split_view_only_training.py
```


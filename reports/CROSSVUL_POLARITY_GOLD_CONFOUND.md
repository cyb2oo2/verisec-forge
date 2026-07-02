# CrossVul Polarity / Gold Confound Measurement

Closes the open question flagged in `reports/REPAIR_ANTISYMMETRIC_RESULT_V1.md`'s
CrossVul transfer section: CrossVul's higher raw canonical accuracy and worse
polarity flip behavior than PrimeVul *may* be explained by a stronger
net-polarity/gold correlation there, and that report explicitly said "this was
not separately measured." This measures it, on the exact same 350 CrossVul
base pairs used for #54's repair-transfer test, paralleling
`reports/POLARITY_GOLD_CONFOUND.md`'s PrimeVul/DeltaSecommits/PatchEval
analysis. Reproduce:

```powershell
.\.venv\Scripts\python.exe scripts\analyze_crossvul_polarity_gold_confound.py
```

Output: `reports/crossvul_polarity_gold_confound_v1.json`. Pure counting over
existing rows and one lookup into already-generated model predictions from
#54; **no model is trained or run** here.

## This PR's claim boundary

This is a **dataset/presentation-structure analysis, not a model-quality
claim**. It measures how Side A/Side B and net changed-line polarity relate to
gold on CrossVul, so CrossVul's canonical-accuracy and polarity-sensitivity
numbers can be read on a comparable footing to PrimeVul's. It does not by
itself establish that the model reasons better or worse on either source.

## Dataset used

The same 350-pair CrossVul canonical / polarity-only-swap / side-swap audit
built for #54's repair-transfer test
(`data/processed/secure_code_crossvul_polarity_only_swap_audit_v1.jsonl`,
1050 rows: 350 pairs × 3 variants), no new construction. Verified against the
raw CrossVul source
(`data/processed/secure_code_crossvul_pair_diff_eval_metadata.jsonl`):

| Quantity | Value |
| --- | ---: |
| raw source rows | 8742 |
| raw source pair keys | 4371 |
| pair keys with exactly 2 rows | 4371 (100%) |
| clean one-vulnerable/one-secure pairs | 4371 (100%), 0 dirty |

Every pair key groups cleanly to one vulnerable and one secure row, matching
the precondition `build_canonical_pair`
(`src/vrf/relational_benchmark.py`) enforces when constructing base pairs —
the same construction path used for PrimeVul/DeltaSecommits/PatchEval and for
the 350-pair CrossVul sample in #54.

CrossVul is evaluated **zero-shot** (the checkpoint was never trained on it),
so there is no CrossVul training set to check for orientation-augmentation the
way PrimeVul's training data is checked in
`reports/POLARITY_GOLD_CONFOUND.md`. The applicable analog is the eval
benchmark's own gold-side balance:

| Quantity | PrimeVul eval | CrossVul eval |
| --- | ---: | ---: |
| canonical rows | 600 | 350 |
| gold_riskier_side == A | 48.3% | 52.6% (184/350) |

Both are reasonably balanced (Side A/Side B assigned independently of
vulnerability, as `build_canonical_pair`'s stable-hash assignment guarantees
by construction), so the eval-set orientation itself is not a source of
asymmetry on either side.

## Net-polarity / gold correlation: CrossVul is measurably stronger

Net polarity = whether the rendered hunk is net-additive (`+` > `-` changed
lines) or net-subtractive. The crude shortcut is "net-added -> base/Side A
riskier; net-removed -> Side B" (same definition as the PrimeVul analysis, no
new metric).

| Split | PrimeVul shortcut accuracy | CrossVul shortcut accuracy |
| --- | ---: | ---: |
| canonical | 0.706 | **0.855** |
| `polarity_only_swap` (gold fixed, polarity flipped) | 0.312 | **0.151** |
| `side_swap` | 0.688 | **0.849** |

On both sources the shortcut is strongly predictive on canonical data and
inverts under a polarity-only flip with gold held fixed — but on CrossVul the
effect is larger in both directions: higher canonical shortcut accuracy
(0.855 vs. 0.706) and a more extreme inversion (0.151 vs. 0.312, further below
the 0.5 chance line). By this measure, **CrossVul's net-polarity/gold
correlation is stronger than PrimeVul's, not weaker or comparable.**

Full contingency (`P(gold=A | net_added)`, `P(gold=A | net_removed)`) is in
the JSON artifact; the pattern is consistent across all three variants.

## The frozen baseline model tracks the crude shortcut far more closely on CrossVul

This is the more striking number. Per-row agreement between the (pre-repair,
un-repaired) model's prediction and the crude net-polarity shortcut:

| Variant | PrimeVul model-vs-shortcut agreement | CrossVul model-vs-shortcut agreement |
| --- | ---: | ---: |
| canonical | 0.562 | **0.915** |
| `polarity_only_swap` | 0.577 | **0.926** |
| `side_swap` | 0.581 | **0.930** |

On PrimeVul the model does **not** reduce to the crude line-count rule
(~56-58% agreement, only modestly above what a random-but-correlated predictor
would show). On CrossVul, the same frozen model's predictions align with the
crude shortcut on **over 90%** of rows across all three variants — a
qualitatively different relationship between the model's behavior and this
one crude, task-illegitimate feature.

## Interpretation

CrossVul's higher canonical accuracy should not be read as stronger
secure-code reasoning by itself. The measured polarity/gold structure
indicates that presentation-correlated shortcuts can make canonical accuracy
look better while leaving relation robustness poor: CrossVul's net-polarity/
gold correlation is measurably stronger than PrimeVul's (0.855 vs. 0.706
canonical shortcut accuracy), and the frozen baseline model's predictions
track that crude shortcut far more closely there (~92% vs. ~57% row
agreement). This is consistent with, though this analysis alone does not
prove, part of CrossVul's higher raw canonical accuracy and worse polarity
flip rate being attributable to the source having a stronger presentation
shortcut rather than the model applying stronger secure-code reasoning to an
unseen source.

This does **not** mean "CrossVul accuracy is fake," and it does **not** mean
"the model generalizes better" or "the model generalizes worse" to CrossVul in
general — canonical accuracy alone was never a sufficient signal for either
claim, on either source, which is the project's starting thesis. What this
measurement adds is a concrete, source-specific reason the two sources'
canonical-accuracy numbers are not on equal footing and should not be compared
as if they were.

## Bearing on #54's flagged caveat

This resolves the open question, and resolves it toward the "stronger
confound" reading, not a null result. `reports/REPAIR_ANTISYMMETRIC_RESULT_V1.md`
should be read with this in mind wherever it cites CrossVul's raw canonical
accuracy (0.786 independent-inference baseline) without this context.

## Scope

One checkpoint (the pre-repair baseline; the repaired checkpoint's predictions
were not separately re-checked against the shortcut since the frozen-model
question is what was open), 350 CrossVul pairs, one length (1024). See
`docs/EXPERIMENT_COMPLETENESS_AUDIT.md` for how this fits the broader
evidence-gap picture.

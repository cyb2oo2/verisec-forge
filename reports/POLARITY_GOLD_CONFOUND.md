# Polarity / Gold Confound Measurement

Backs the claim boundary in `docs/TASK_FORMULATION.md` with measured numbers.
Reproduce with:

```powershell
.\.venv\Scripts\python.exe scripts\analyze_polarity_gold_confound.py
```

Output: `reports/secure_code_polarity_gold_confound_v1.json`. Pure counting over
existing rows; no model is trained or run.

## Question

The side-order arc shows the classifier's riskier-side decision is causally
sensitive to diff-hunk polarity. Is that a shortcut? It is a shortcut only if
(a) the task treats polarity as nuisance and (b) polarity is not the legitimate
answer. This report separates two notions of polarity and measures each against
gold.

## Rendering orientation is de-confounded from gold

Orientation = which side is the diff "from"/base side (rendered on `-`/`---`).
In VeriPatch-RR that is always Side A, and `build_canonical_pair` assigns
Side A/Side B by a stable hash, independent of which side is vulnerable.

Training data for the checkpoint
(`secure_code_primevul_joint_side_choice_train_v1.jsonl`):

| Quantity | Value |
| --- | ---: |
| rows | 6000 |
| `observed` (forward) / `synthetic_reverse` | 3000 / 3000 |
| fraction vulnerable side == A | 0.500 |
| source pairs | 2269 |
| source pairs rendered in both orientations | 2269 (100%) |

Every training pair is shown in both orientations with labels tracking the true
vulnerable side. **Naive both-orientation augmentation is already present in
training** and did not produce polarity-invariance -- the eventual repair cannot
just re-apply it.

## Net changed-line polarity is a predictive-but-illegitimate feature

Net polarity = whether the rendered hunk is net-additive (`+` > `-` changed
lines) or net-subtractive. Real fixes add guards more than they delete code, so
this correlates with the vulnerable side. The crude shortcut is "net-added ->
base/Side A riskier; net-removed -> Side B."

| Split | P(gold=A \| net_added) | P(gold=A \| net_removed) | shortcut accuracy |
| --- | ---: | ---: | ---: |
| training pairs | 0.855 | 0.145 | **0.855** |
| eval `canonical` | 0.818 | 0.338 | **0.706** |
| eval `polarity_only_swap` (gold fixed, polarity flipped) | 0.154 | 0.617 | **0.312** |
| eval `side_swap` | 0.846 | 0.383 | 0.688 |

The shortcut is strongly predictive on canonical data and **inverts to below
chance** when polarity is flipped with gold held fixed -- the mechanical reason
a polarity-bound model's accuracy collapses `0.66 -> 0.345`.

## The model does not reduce to the crude heuristic

Aggregate accuracy alignment is not mechanism. Per-row agreement between the
model's prediction and the net-polarity shortcut:

| Variant | model-vs-shortcut agreement | model A-rate |
| --- | ---: | ---: |
| `canonical` | 0.562 | 0.665 |
| `polarity_only_swap` | 0.577 | 0.680 |
| `side_swap` | 0.581 | 0.660 |

At ~56-58% the model does **not** implement the crude line-count rule. Its
polarity sensitivity is real (the polarity-only swap moves the prediction to
near-independence, `phi = -0.094`) but its functional form is unidentified. We
report *that* polarity drives the decision, not *which* polarity feature.

## Bearing on the claims

* Confirms polarity is a legitimate nuisance variable under the
  candidate-identity task (orientation de-confounded from gold), so the
  polarity-only-swap collapse is a genuine relational failure, not valid
  directional inference.
* Reframes the result as a spurious-correlation shortcut (predictive but
  task-illegitimate), the standard shortcut-learning setup.
* Preempts the "just augment both orientations" dismissal: augmentation is
  already in training and did not fix it.
* Keeps the mechanism claim behavioral and bounded: the model is sensitive to
  polarity but is not the crude heuristic, and no internal-binding claim is made.

One checkpoint, one length (1024), 600 eval pairs. See `docs/TASK_FORMULATION.md`
for the full claim boundary.

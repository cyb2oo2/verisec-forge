# CodeBERT Label/Polarity Mechanism Replication

Tests whether the label-vs-polarity side-order mechanism established on Qwen
(#46–#49) is Qwen-specific or also appears in a competency-matched non-Qwen
model. The `docs/EXPERIMENT_COMPLETENESS_AUDIT.md` flagged single-architecture
mechanism evidence as the remaining must-run item before a serious paper draft.

**No model was trained, tuned, or redesigned for this.** An existing CodeBERT
checkpoint is run in inference over the same 600 base pairs used in the Qwen
chain. Reproduce:

```powershell
.\.venv\Scripts\python.exe scripts\build_label_polarity_mechanism_audit.py
.\.venv\Scripts\python.exe scripts\materialize_relational_runtime.py `
  --model-id codebert-label-polarity-512 `
  --tokenizer checkpoints\cls_secure_code_primevul_joint_side_choice_codebert_v1 `
  --max-length 512 --local-files-only `
  --benchmark data\processed\secure_code_label_polarity_mechanism_audit_v1.jsonl `
  --output data\processed\secure_code_label_polarity_mechanism_audit_v1_codebert_runtime512.jsonl
.\.venv\Scripts\python.exe scripts\predict_encoder_relational_audit.py `
  --checkpoint checkpoints\cls_secure_code_primevul_joint_side_choice_codebert_v1 `
  --dataset data\processed\secure_code_label_polarity_mechanism_audit_v1_codebert_runtime512.jsonl `
  --output outputs\secure_code_label_polarity_mechanism_codebert_predictions_512.jsonl
.\.venv\Scripts\python.exe scripts\analyze_codebert_label_polarity_mechanism.py
```

Artifact: `reports/codebert_label_polarity_mechanism_replication_v1.json`.

## Checkpoint and competency match

- Checkpoint: `checkpoints/cls_secure_code_primevul_joint_side_choice_codebert_v1`
  (RoBERTa/CodeBERT sequence classifier, max length 512). Trained on the same
  6,000 bidirectional side-choice rows as the cross-model audit
  (`reports/CROSS_MODEL_RELATIONAL_AUDIT.md`); **no new training here**.
- Canonical accuracy: **0.677** (CodeBERT) vs **0.660** (Qwen decoder
  classifier on the same 600-pair mechanism base). Close enough that the
  comparison is competency-matched, consistent with the cross-model audit's
  67.67% / 65.50% canonical numbers.

## Dataset

Combined 4-variant audit on the same 600 PrimeVul/DeltaSecommits/PatchEval base
pairs the Qwen chain used, merged from the two committed base audits
(`scripts/build_label_polarity_mechanism_audit.py`, verified byte-identical
canonical rows/gold across sources): 600 pairs × {canonical, label_only_swap,
polarity_only_swap, side_swap} = **2400 rows**. Materialized for CodeBERT at
length 512, `transformation_introduced_critical_truncation_rows: 0` for every
variant.

**Runtime caveat.** CodeBERT at 512 truncates the critical hunk on 178/600 rows
per variant (mean critical-line visibility ~0.76), lower than Qwen's 1024-length
run. The truncation is identical across variants (0 transformation-introduced),
so the *within-CodeBERT* label-vs-polarity contrast is fair, but CodeBERT's
absolute canonical accuracy sees less of the changed hunk than Qwen's did.

## Result: the label-vs-polarity ordering reproduces

The Qwen finding was an *ordering*: swapping the "Side A"/"Side B" prose labels
barely moves the prediction (phi near +1, inert), while flipping the diff hunk
polarity moves it to near-independence (phi near 0). CodeBERT shows the same
ordering, more sharply.

| Comparison (vs canonical) | Qwen phi | CodeBERT phi |
| --- | ---: | ---: |
| `label_only_swap` (labels swapped, polarity fixed) | **+0.914** | **+0.988** |
| `polarity_only_swap` (polarity flipped, labels/gold fixed) | **−0.094** | **−0.193** |
| `side_swap` (both) | −0.024 | −0.189 |
| cross-check `polarity_only_swap` vs `side_swap` (inert words) | +0.892 | +0.992 |

| Variant accuracy (gold-referenced) | Qwen | CodeBERT |
| --- | ---: | ---: |
| canonical | 0.660 | 0.677 |
| `label_only_swap` | 0.348 | 0.322 |
| `polarity_only_swap` (gold fixed) | **0.345** | **0.352** |
| `side_swap` | 0.665 | 0.648 |

On both models, relabeling leaves the prediction essentially frozen (accuracy
falls to ≈ 1 − canonical as gold flips underneath an unchanged prediction),
while a polarity flip with gold held fixed collapses accuracy by roughly half.
The `polarity_only_swap` ≈ `side_swap` cross-check (phi +0.992) confirms the
prose words are inert for CodeBERT too — the diff body drives the decision.

**A competency-matched non-Qwen model reproduces the behavioral pattern:
predictions are much more sensitive to diff-hunk polarity than to prose
side-label changes. This broadens the mechanism evidence beyond Qwen, but
remains behavioral evidence rather than an internal mechanistic explanation.**

## Where CodeBERT differs from Qwen: it *does* reduce to the crude shortcut

One quantity differs sharply, and it is worth stating rather than smoothing
over. Per-row agreement between the model's prediction and the crude
net-polarity line-count shortcut ("net-added ⇒ Side A riskier"):

| Split | Qwen agreement | CodeBERT agreement |
| --- | ---: | ---: |
| PrimeVul canonical | ~0.57 | **0.966** |
| PrimeVul `polarity_only_swap` | ~0.58 | 0.964 |
| CrossVul canonical | ~0.92 | 0.933 |
| CrossVul `polarity_only_swap` | ~0.93 | 0.898 |

On PrimeVul, Qwen does **not** reduce to the crude line-count heuristic (~0.57,
its polarity sensitivity is some richer representation), whereas **CodeBERT's
predictions align with the crude shortcut on ~96% of PrimeVul rows** — for
CodeBERT the polarity mechanism largely *is* the net-added-vs-removed line
count. So the two architectures share the same behavioral ordering (polarity
disruptive, labels inert) but differ in the *functional form* of the polarity
sensitivity: cruder in CodeBERT, richer in Qwen. This is a difference in
mechanism detail, not a contradiction of the shared finding.

## CrossVul confound-aware check

Because #58 (`reports/CROSSVUL_POLARITY_GOLD_CONFOUND.md`) showed CrossVul
carries a stronger polarity/gold confound than PrimeVul, the CodeBERT
replication was also run on the 350-pair CrossVul audit (materialized for
CodeBERT at 512, `transformation_introduced_critical_truncation_rows: 0`).

- CodeBERT CrossVul model-vs-crude-shortcut agreement: **0.933** canonical
  (Qwen ~0.92) — both architectures track the crude shortcut heavily on
  CrossVul, consistent with #58's finding that CrossVul's presentation shortcut
  is strong.
- CodeBERT CrossVul canonical accuracy is 0.763 and `polarity_only_swap`
  collapses to 0.274. Per #58, **this higher raw CrossVul canonical accuracy
  should not be read as stronger reasoning** — it coincides with a stronger
  presentation shortcut that both models lean on.

This check was feasible in-PR (CodeBERT inference is ~2.5 s for 1050 rows), so
it is included rather than deferred.

## Claim boundary

- This is behavioral mechanism evidence on **one additional** architecture,
  competency-matched on canonical accuracy. It does **not** show "the mechanism
  is universal," that "all models fail this way," or that "CodeBERT proves
  generality" — two architectures is broader than one, not general.
- No internal/mechanistic claim: predictions are causally sensitive to polarity
  under controlled input interventions; no probing or activation evidence is
  offered, and none is claimed.
- One checkpoint per architecture, one length each (Qwen 1024, CodeBERT 512),
  600 mechanism pairs + 350 CrossVul pairs. CodeBERT's 512 truncation caveat
  (above) applies to its absolute accuracy, not to the within-model
  label-vs-polarity contrast.
- CrossVul raw canonical accuracy is not a reasoning claim (see #58).

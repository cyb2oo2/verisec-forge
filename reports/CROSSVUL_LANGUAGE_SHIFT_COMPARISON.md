# CrossVul Language-Shift Comparison

This report tests the other half of `docs/NEXT_PHASE_ROADMAP.md` Current
Gaps item 1: whether the paired-diff detectors generalize across
**language**, not just across source. Both checkpoints here were trained
exclusively on C/C++ paired diffs (PrimeVul, with or without DeltaSecommits,
both C/C++-only sources). This report evaluates them zero-shot on a
CrossVul subset covering PHP, JavaScript, Python, and Java -- four
languages with materially different syntax than anything either checkpoint
has seen in training -- and compares against the C/C++-only CrossVul result
from `reports/CROSSVUL_ZERO_SHOT_PRIMEVUL_CHECKPOINT.md` and
`reports/CROSSVUL_ZERO_SHOT_MATCHED_MIXED_CHECKPOINT.md`.

## Protocol

- Source dataset: `crossvul (data/raw/crossvul_train_raw.jsonl)`
- Multi-language subset: `php`, `javascript`, `python`, `java` (`3,780` pairs
  / `7,560` rows; `php` dominates at `2,139` of the `3,780` pairs)
- C/C++ subset (comparison baseline): `4,371` pairs / `8,742` rows, from the
  prior reports
- Threshold: `0.5`
- Pair-coupling margin: `0.02`
- Both checkpoints trained exclusively on C/C++ paired diffs; neither has
  seen CrossVul or any non-C/C++ language in training

## Results

| Checkpoint | Eval subset | Default BA | Pair-coupled BA | Group all-correct (pair-coupled) |
| --- | --- | ---: | ---: | ---: |
| Single-source (PrimeVul only) | C/C++ | 0.7793 | 0.8061 | 0.7881 |
| Single-source (PrimeVul only) | PHP/JS/Python/Java | 0.7589 | **0.8132** | 0.7902 |
| Matched-mixed (PrimeVul + DeltaSecommits) | C/C++ | 0.8115 | 0.8141 | 0.8026 |
| Matched-mixed (PrimeVul + DeltaSecommits) | PHP/JS/Python/Java | 0.8180 | **0.8316** | 0.8124 |

## Interpretation

Language shift does not produce the additional degradation that the
"broader languages" framing in `docs/NEXT_PHASE_ROADMAP.md` anticipated.
Pair-coupled BA on the multi-language subset is, if anything, slightly
*higher* than on the C/C++ subset for both checkpoints (`+0.0071` for
single-source, `+0.0175` for matched-mixed), and bucket-distribution shape
(changed-line buckets) is comparable between the two subsets, so this is not
an artifact of the multi-language rows being structurally easier by line
count.

This is a genuinely useful, mildly counter-intuitive result. The multi-
language subset is dominated by PHP (`2,139` of `3,780` pairs, `57%`), so
the aggregate result could in principle be a PHP-driven artifact rather than
genuine cross-language transfer. Checked directly: the default-threshold
per-language breakdown shows no language as an outlier --

| Language | Single-source BA | Matched-mixed BA |
| --- | ---: | ---: |
| `java` | 0.7710 | 0.8067 |
| `javascript` | 0.7735 | 0.8205 |
| `php` | 0.7468 | 0.8193 |
| `python` | 0.7795 | 0.8201 |

PHP is, if anything, the *weakest* of the four for the single-source
checkpoint, not an inflated driver of the aggregate. All four languages land
within a `0.03`-`0.04` BA band of each other per checkpoint, comparable to
the spread already seen across PrimeVul/DeltaSecommits/PatchEval/CrossVul-C
in earlier reports. This rules out the most obvious confound, though real
caveats remain:

- This evaluates whether the paired-diff *task formulation* (unified diff,
  vulnerable-vs-fixed classification) transfers across language via the
  underlying Qwen2.5-Coder backbone's broad multi-language pretraining, not
  whether language-specific vulnerability semantics are understood as well
  as C/C++ ones were during LoRA fine-tuning.
- Only four languages were tested, all chosen for sample size in the raw
  CrossVul data, not for representativeness of "broader languages" as a
  category.

## Claim Boundary

This does not establish that the paired-diff formulation is
language-general. It establishes that, on this specific four-language,
PHP-heavy CrossVul subset, two C/C++-only-trained checkpoints do not show
the additional degradation a naive language-shift hypothesis would predict.
Per-language breakdown, a larger and more balanced language sample, and
training-language ablations (e.g. a checkpoint with no C exposure at all)
would be needed before treating this as a general claim about
cross-language transfer.

# Purified Relational Evaluation Protocol (v4)

Status: **in place**. No new model training has been started.

This protocol governs every relational claim made from the v4 suite. Its purpose
is to make it impossible to report a model as relationally competent when a
semantics-free rule matches it.

Suite: `data/processed/secure_code_relational_benchmark_v4.jsonl`
Summary: `reports/secure_code_relational_benchmark_v4_summary.json`
Builder: `scripts/build_relational_benchmark_v4.py`

## 1. A correction to the phase premise

The phase goal was stated as removing "the unfair advantage the polarity control
enjoys from surface glyphs." **Measurement does not support that diagnosis, and
the glyph interventions do not achieve it.**

On identical pairs:

| Control | Rendering | canonical accuracy |
| --- | --- | ---: |
| glyph control | unified diff | `0.8369` |
| prose control | `split_view` (no `+`/`-` anywhere) | `0.8410` |

Stripping the glyph channel does not cost the control anything — it scores
*marginally higher* without glyphs. The control never depended on the encoding.
It depends on the regularity that **security fixes add more characters than they
remove**, which survives any rendering that reveals edit direction.

What does neutralise it is removing that correlation from the sample:

| Slice | glyph control | prose control |
| --- | ---: | ---: |
| Full suite (1,245 pairs) | `0.8369` | `0.8410` |
| **Polarity-balanced (308 pairs)** | **`0.5000`** | **`0.5000`** |

So the glyph work is retained — but as a **transfer measurement**, which is what
it is good for, not as a handicap on the control. The handicap is the balanced
slice.

## 2. Hard requirements

### 2.1 Exact-mirror invariant

`swap_mirror_is_exact` is enforced at load in
`scripts/build_relational_benchmark_v2.py::load_pairs`. A pair is admitted only
when swapping sides exchanges added and removed lines **and** characters exactly.

- Rejection rates are published per source in every benchmark summary.
- A source that loses *every* pair raises `SystemExit` rather than being silently
  dropped — the failure mode that let the DeltaSecommits defect go unnoticed.
- **No relational benchmark may be released containing non-mirror pairs.**

v4 rejection rates:

| Source | pairs seen | single-line records | non-mirror rejected | rate |
| --- | ---: | ---: | ---: | ---: |
| PrimeVul | 827 | 0 | 30 | `0.0363` |
| DeltaSecommits (v2) | 327 | 0 | 11 | `0.0336` |
| PatchEval | 269 | 0 | 40 | `0.1487` |
| CrossVul | 4,371 | 0 | 153 | `0.0350` |

Verified: 1,245 / 1,245 glyph pairs are exact mirrors.

### 2.2 Ingestion normalisation

`is_line_structured` (in `src/vrf/relational_benchmark.py`) names the defect that
the mirror invariant otherwise only detects as a symptom: a source that stores a
whole function on one line. `build_relational_benchmark_v4.py` counts it per
source before the invariant runs, so the cause is visible in the summary.

All four sources now report `single_line_rate = 0.0`. DeltaSecommits was fixed at
ingestion (`normalize_code_for_diff` applied to the emitted `code` field, not
only to `pair_text`).

### 2.3 `autojunk` — decision: keep the default, rely on the filter

`difflib.SequenceMatcher` derives its junk set from the second sequence only, so
matching is direction-dependent past the 200-element threshold. Measured on
CrossVul:

| Option | effect |
| --- | --- |
| `autojunk=False` | recovers 128 of 153 rejected pairs (**+3.0%**) |
| `autojunk=False` | **changes the rendering of 477 / 4,218 (11.3%) currently-valid pairs** |

**Decision: retain `autojunk=True` (the stdlib default) and rely on the
exact-mirror filter.** Recovering 3% of pairs does not justify silently altering
11.3% of valid renderings, which would invalidate every existing prediction
artifact and force full re-materialisation and re-inference. The filter is
cheaper, safer, and already published. Revisit only if a future suite is being
built from scratch anyway.

## 3. Reporting requirements

### 3.1 The control is a mandatory baseline

Every model result must be reported beside the strongest semantics-free control
on the same pairs (Standing Rule 8). A model that does not beat it, with a
pair-clustered interval excluding zero, **has not demonstrated relational
understanding** and must not be described as doing so.

### 3.2 Both renderings, side by side

Report the glyph family and the prose family together. A single-rendering number
is not a relational result.

| | glyph | prose | transfer gap |
| --- | --- | --- | --- |
| model | … | … | prose − glyph |
| control | … | … | prose − glyph |

### 3.3 Glyph→prose transfer failure is a first-class negative result

The control's transfer gap is approximately zero (`0.8369` → `0.8410`). A model
whose gap is large has not learned the relation; it has learned the encoding.
This must be reported as a headline negative, not a footnote.

Current measured gaps (350 CrossVul pairs):

| System | glyph | prose | gap |
| --- | ---: | ---: | ---: |
| control | `0.8057` | `0.8029` | `-0.0028` |
| baseline classifier | `0.7429` | `0.4886` | **`-0.2543`** |
| repaired antisym | `0.7714` | `0.5486` | **`-0.2228`** |

### 3.4 The balanced slice is the headline

Primary claims are made on `polarity_balanced_slice` (308 pairs), where both
controls sit at exactly `0.5000`. Full-suite numbers remain reportable as
secondary context, always beside the control.

## 4. Known residual shortcuts

Recorded in the v4 summary under `shortcuts_NOT_removed`:

- **Net-polarity magnitude.** Within the balanced slice, a threshold rule refit
  on `|net chars|` still reaches `~0.58–0.59`. That figure is refit on the
  evaluation set itself, so it is an optimistic upper bound, but it is not
  chance. Magnitude stratification is the next lever if it proves to matter.
- **Glyph encoding is not a shortcut against the control** — see §1. It is a
  shortcut the *model* relies on, which is why the transfer gap is measured.

## 5. Training gate

New model training is **blocked** until:

1. Any training variant is evaluated under §3 on the v4 suite. ✔ available
2. The balanced slice is used for headline claims. ✔ available
3. The control is reported alongside every result. ✔ mandated

Planned training variants (glyph-stripped, prose-native, randomised markers)
remain **not started**, per instruction. When they begin, the prose family is
already materialised for all four sources, so a prose-native model can be trained
without building new data.

The one design note to carry into that work: a prose-native model must still beat
the *prose* control (`0.8410` full / `0.5000` balanced). Training without glyphs
removes the model's shortcut, not the control's baseline.

# Arc 2: Revised Main Line

Supersedes the relational-arc framing in `paper/main_claims.md` and
`paper/workshop_draft_v1.md`. Evidence:
[VeriPatch-RR Structural Control](../reports/VERIPATCH_RR_STRUCTURAL_CONTROL.md),
artifact `reports/veripatch_rr_structural_control_v1.json`.

## Why the previous main line was withdrawn

The relational arc was built on the premise that models are *pointwise competent
but relationally inconsistent*, with side-order consistency as the open problem
and the antisymmetric readout as a structural fix that "preserves canonical
accuracy."

Applying Standing Rule 8 — compare against the strongest semantics-free control —
to the relational arc for the first time removes that premise:

- The fine-tuned classifier is **behind** a character-counting rule on every
  well-formed source, on both canonical accuracy and both-directions-correct.
- The repaired antisymmetric system — the strongest in the repository — is
  **statistically indistinguishable** from that rule: PrimeVul both-correct
  `0.8400` vs `0.8400` (`p=1.0`), PatchEval `+0.0050` (`p=1.0`), CrossVul
  `+0.0029` (`p=1.0`).
- Its one measured advantage is confined to DeltaSecommits, where 100% of rows
  are malformed by a source ingestion defect.

This is the same signature that ended Arc 1 (`+0.0008`, sign test 19–18,
`p=1.0`). "Relational consistency is the hard open problem" is not supportable:
a five-line rule is more accurate *and* equivariant wherever the benchmark
renders a valid swap.

## Revised thesis

> Fine-tuning on paired secure-patch data does not produce relational patch
> understanding exceeding a semantics-free polarity rule. The classifier binds to
> the `+`/`-` glyph channel and has no content-based fallback; and the benchmark's
> own side-swap construction is corrupted on one third of the representative
> suite, which inflated every prior relational measurement.

Two findings carry it. Both survive the strongest control because neither is a
performance claim.

## Finding 1 — The glyph-channel binding (mechanism)

**Claim.** The classifier's competence is bound to the `+`/`-` glyph encoding.
The identical patch relation stated in natural language is unusable to it.

**Evidence.** The `split_view` transform regroups identical content into
`Removed from Side A` / `Added in Side B` blocks with no `+`/`-` glyphs.

| Quantity | Value |
| --- | ---: |
| Model accuracy, `canonical__split_view` | `0.5133` |
| Model accuracy, `side_swap__split_view` | `0.4850` |
| Model accuracy, other four nuisance families | `0.62`–`0.65` |
| **Prose control** (same rule, reads block headers) | **`0.8433`** |
| Glyph control on the canonical unified diff | `0.7217` |

The critical control is the last two rows. `split_view` does **not** ablate
polarity — it re-encodes it, and a semantics-free character rule reading the
prose headers extracts it *better* than the same rule reads the unified diff
(`0.8433` vs `0.7217`). The information is present, sufficient, and more
accessible than before. The model is at chance on the same rows.

**Why this is stronger than the prior framing.** `POLARITY_GOLD_CONFOUND.md`
established behavioral polarity sensitivity but explicitly left the functional
form "unidentified" (~56% agreement with the crude rule). The prose control
identifies it: the dependency is on the glyph channel, not on the relation.

**Replicated on an external source.** CrossVul nuisance families were built and
run ([report](../reports/SPLIT_VIEW_PROSE_CONTROL_CROSSVUL_V3.md)), 350 pairs,
zero-shot:

| System | canonical | equivariance | both-correct |
| --- | ---: | ---: | ---: |
| prose control on `split_view` | `0.8029` | `0.9829` | `0.8000` |
| *glyph control on the canonical diff, same pairs* | *`0.8057`* | *`0.9800`* | *`0.7943`* |
| baseline independent on `split_view` | `0.4886` | **`0.0514`** | `0.0343` |
| repaired antisym on `split_view` | `0.5486` | exact | `0.5486` |

The first two rows are the same numbers, which proves the re-encoding is
lossless. CrossVul also shows a sharper form of the effect than the pooled
three-source measurement: equivariance falls to `0.0514`, meaning the model
returns the **same answer** on canonical and swapped renderings for 94.9% of
pairs. Without the glyph channel the decision does not merely degrade — it
freezes, and both-directions-correct collapses to `0.0343` as a consequence.

**Convergent evidence.** `QWEN_LABEL_ONLY_SWAP_VS_STRUCTURAL_SWAP.md` found
swapping the prose side labels leaves the prediction nearly frozen
(`phi = +0.914`). Two independent interventions — one removing glyphs, one
rewriting labels — give the same answer: prose is invisible to this classifier.

**It also resolves an open item.** The `0.925` `split_view` side-swap violation
rate that `REPAIR_ANTISYMMETRIC_RESULT_V1.md` parked as "a data point for future
mechanism work" follows directly: with the glyph channel gone there is no
content-based behavior to fall back to.

**Boundary.** One checkpoint, one length, 600 pairs, one transform family.
Behavioral and correlational; no internal-mechanism claim.

## Finding 2 — The side-swap construction defect (infrastructure)

**Claim.** One third of the representative suite cannot support a side-swap
measurement, because the rendered rows have no line-level polarity structure.

**Root cause — corrected.** This is *not* `difflib` asymmetry. Recomputing
opcodes directly on source code, with and without `autojunk`, `char_net` is
exactly antisymmetric on 100% of pairs. The defect is upstream: some sources
store a whole function on one line with no trailing newline, so
`difflib.unified_diff` emits the added body on the same physical line as the
removed body.

| Source | single-line `code` records | broken swap mirrors |
| --- | ---: | ---: |
| PrimeVul | 0% (0/400) | 0 / 200 |
| PatchEval | 1.75% (7/400) | 25 / 200 |
| DeltaSecommits | **100% (400/400)** | **200 / 200** |
| CrossVul | — | 345 / 350 mirrored |

**Impact.** Every side-swap equivariance, both-directions-correct, and robust
accuracy number computed over the mixed suite is contaminated. The mixed-suite
exact-mirror rate is `0.6250`. On DeltaSecommits the control's
both-directions-correct is `0.0000` — not because it is wrong, but because
nothing in the rendering flips.

### Status: fixed

**1. Ingestion fixed.** `scripts/build_deltasecommits_pair_diff.py` now applies
`normalize_code_for_diff` to the emitted `code` field, not only to `pair_text`.
The function already existed; it was simply never reaching the field the
relational benchmark consumes. Re-materialized to
`..._cpp_eval_metadata_v2.jsonl`:

| Check | v1 | v2 |
| --- | ---: | ---: |
| single-line `code` records | 100% (654/654) | 0% (0/654) |
| exact swap mirror | 0% (0/327) | 99.39% (325/327) |
| `pair_text` byte-identical to v1 | — | **654/654** |

The `pair_text` regression check matters: every prior DeltaSecommits report is
built on `pair_text`, and none of them change.

**2. Construction-time invariant added.**
`src/vrf/relational_benchmark.py::swap_mirror_is_exact` requires that swapping
sides exchanges added and removed lines *and* characters exactly.
`scripts/build_relational_benchmark_v2.py` now rejects failing pairs at load and
publishes the rate:

| Source | eligible pairs | rejected | rejection rate |
| --- | ---: | ---: | ---: |
| PrimeVul | 797 | 30 | `0.0363` |
| DeltaSecommits (v2) | 316 | 11 | `0.0336` |
| PatchEval | 229 | 40 | `0.1487` |

PatchEval's `0.1487` is well above its `0.0175` single-line rate, so it has
additional non-mirror causes the invariant now catches. The rebuilt benchmark
(`secure_code_relational_benchmark_v3.jsonl`) is **600/600 exact mirrors across
all three sources**.

**3. The corrupted source was carrying the repair's only win.** On the repaired
benchmark the semantics-free control scores:

| Source | canonical | equivariance | both-directions-correct |
| --- | ---: | ---: | ---: |
| DeltaSecommits | `0.8850` | `0.9800` | **`0.8750`** |
| PrimeVul | `0.8500` | `0.9800` | `0.8400` |
| PatchEval | `0.7950` | `0.9900` | `0.7950` |

**Resolved.** Both checkpoints were re-run on the v3 renderings
([v3 report](../reports/VERIPATCH_RR_STRUCTURAL_CONTROL_V3.md)). The
DeltaSecommits advantage reverses:

| DeltaSecommits, both-directions-correct | control | repaired antisym | delta |
| --- | ---: | ---: | ---: |
| v1 (contaminated) | `0.0000` | `0.6000` | `+0.6000` |
| **v3 (repaired)** | **`0.8700`** | `0.8200` | **`-0.0500`** |

Pooled over all 600 clean pairs, the strongest system trails the control by
`-0.0317` on canonical accuracy (CI `[-0.0567, -0.0083]`) and `-0.0267` on
both-directions-correct (CI `[-0.0533, -0.0033]`). **No learned system in this
repository exceeds the control on any source or metric.**

The fine-tuning increment over the projection null also vanishes: `+0.0267`
(21 fixed / 5 broken, `p=0.002`) on the contaminated suite becomes `+0.0000`
(6 fixed / 6 broken, `p=1.0`) on the repaired one. The two checkpoints differ on
1,799 of 1,800 raw probabilities, so this is a real null, not a code artifact.

The antisymmetric readout's structural properties are unaffected: equivariance
is exactly `1.0` by construction and it lifts both-directions-correct from
`0.6383` (independent) to `0.8117`. It simply does not reach the control's
`0.8383`.

## The two open questions

**Q1. Why does no content-based signal emerge once the glyph channel is
ablated?** The training data contains both orientations of every pair
(`3000/3000`, 100% of pairs in both orientations — `POLARITY_GOLD_CONFOUND.md`),
so naive augmentation is already present and did not induce content reading. The
question is whether a content-based representation is absent, or present but
unreachable through the glyph-dominated readout.

Discriminating experiment: train on `split_view` renderings alone (glyph channel
unavailable from the start) and test whether canonical accuracy exceeds the
prose control's `0.8433`. If it does not, the ceiling is the polarity statistic
itself, not the encoding.

**Q2. How should relational benchmarks be constructed so side-swap evaluation is
sound?** Finding 2 shows the failure is silent: the suite reported 1,200 pair
rows and 9,600 total rows with no indication that a third could not support the
measurement. Required: an exact-mirror invariant enforced at construction, a
published rejection rate, and per-source stratification by default.

## What this main line does not claim

- Not that fine-tuning cannot exceed diff-shape structure — only that no system
  in this repository does, on these populations.
- Not an internal-mechanism result. Both findings are behavioral.
- Not a deployment or scanner claim.
- Not a repair. The antisymmetric readout remains exact-by-construction and
  remains tied with the control on every well-formed source.

## Documents requiring update

| Document | Required change |
| --- | --- |
| `paper/main_claims.md` | Contributions 1–4 rest on the withdrawn premise; no correction banner present. Replace with the two findings above. |
| `paper/workshop_draft_v1.md` §3 | Contains the sentence withdrawn in `RESEARCH_INTEGRITY_REMEDIATION.md:117` ("protecting the claim that the paired task carries real relational signal"). |
| `paper/workshop_draft_v1.md` §6 | "preserves canonical accuracy" is true but ties a control with no model. |
| `docs/RESULT_STATUS_LEDGER.md` | Add the relational-arc withdrawals and the DeltaSecommits contamination. |
| `reports/RELATIONAL_BENCHMARK_V2.md` | Add the construction defect, the invariant, and per-source rejection rates; supersede with a v3 description. |

## Evaluation protocol

The purified v4 suite and its reporting rules are in
[PURIFIED_EVALUATION_PROTOCOL.md](PURIFIED_EVALUATION_PROTOCOL.md): all four
sources under the exact-mirror invariant, both glyph and prose renderings
materialised, and a polarity-balanced slice on which both controls sit at exactly
`0.5000`. New model training is gated on that protocol and has not been started.

## Out of scope for this rebuild

The `changed_hunk` readout's `99.83%` post-diff consistency is a definitional
consequence of causal attention — appending a suffix cannot change hidden states
at earlier positions — not an empirical measurement. That belongs to the readout
arc and is tracked there; it is deliberately **not** folded into this main line,
which rests only on the two findings above.

## CrossVul transfer leg — complete

CrossVul was re-materialized under the invariant
([report](../reports/VERIPATCH_RR_STRUCTURAL_CONTROL_CROSSVUL_V3.md)): 153/4,371
pairs rejected (3.50%), 4,218 eligible, sampled audit 350/350 exact mirror.
Reported separately from the three-source suite, since it is an external
zero-shot transfer check.

| System | canonical | equivariance | both-correct |
| --- | ---: | ---: | ---: |
| **control** | **`0.8057`** | `0.9857` | **`0.7971`** |
| repaired antisym | `0.7714` | exact | `0.7714` |
| repaired independent | `0.7429` | `0.7371` | `0.6086` |

No system exceeds the control; the strongest trails by `-0.0343` canonical
(CI `[-0.0657, -0.0029]`). This replicates the three-source result on an
external source the checkpoints never saw.

### Second defect identified: `difflib` autojunk asymmetry

CrossVul has **zero** newline-free records yet still rejects 3.50%, which
isolates a cause distinct from the DeltaSecommits defect.
`difflib.SequenceMatcher` derives its junk set from the second sequence only, so
matching is direction-dependent once a side reaches the 200-element autojunk
threshold. On the 153 rejections: 86.27% involve a side with ≥200 lines, and
83.66% become exact mirrors under `autojunk=False`.

This **corrects** the earlier statement that "`difflib` is not the culprit" —
true for DeltaSecommits (a newline defect), but wrong as a general claim. There
are two independent causes:

| Cause | Affected | Status |
| --- | --- | --- |
| Newline-free source records | 100% of DeltaSecommits, 1.75% of PatchEval | fixed at ingestion |
| `difflib` autojunk asymmetry | ~3% of every source | rejected by the invariant |

Q2 of the open questions therefore has a concrete second answer: a relational
benchmark must either pass `autojunk=False` to its differ or enforce an
exact-mirror invariant. This repository now does the latter.

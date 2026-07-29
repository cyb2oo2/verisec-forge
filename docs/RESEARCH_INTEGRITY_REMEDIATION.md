# Research Integrity Remediation Notice

This repository underwent an independent code audit followed by a remediation
pass. Ten audit findings were reproduced against the tree; all ten confirmed.
This notice records what changed, what was withdrawn, and what is now claimed.

Machine-generated evidence:
[verification report](RESEARCH_INTEGRITY_VERIFICATION.md) ·
[status ledger](RESULT_STATUS_LEDGER.md) ·
provenance manifest at `reports/REPRODUCTION_PROVENANCE.json`.

## Reproduce everything

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python scripts/download_reproducibility_bundle.py \
  --bundle-name primevul_router_and_evidence_coupled_inputs --restore
python scripts/run_clean_reproduction.py
python -m pytest -q
```

`run_clean_reproduction.py` fails with a non-zero exit if any required artifact
is missing, naming the artifact and the command that produces or fetches it. It
never substitutes historical values.

## What changed, and why

### 1. Silent fallback to hardcoded results removed

`scripts/build_primevul_pair_coupled_significance_summary.py` previously wrapped
its input load in `except FileNotFoundError` and returned the constant
`[0.8158, 0.8382, 0.8321]`. Because zero `reports/*_threshold_sweep.json` files
exist in the tree, the script exited 0 and published the headline mean `0.8287`
and its interval with **no computation behind them**.

The constant and the handler are gone. Result builders now call
`vrf.artifact_guard.require_artifact`, which raises a `MissingResearchArtifact`
naming the file, what produces it, and how to fetch it.

### 2. The missing negative control was added

The three published controls (metadata-only, candidate-only, counterpart-only)
all *remove* the diff, so none of them could test whether diff structure alone
solves the task. `src/vrf/polarity_control.py` adds semantics-free rules that
read only added/removed line counts — never line content — fit on train and
applied unchanged to the untouched eval split.

The strongest such rule reaches **BA 0.7932** against a reported mainline of
`0.8287`. The learned detector agrees with it on **95.25%** of rows and is
**14.20%** accurate where it errs — below chance, meaning the detector follows
the shortcut into its errors rather than correcting them. Diff *size* alone
(`total_changed_lines`) sits at `0.4972`, confirming the signal is specifically
direction, not magnitude.

### 3. The circular evidence target was withdrawn

`support_label_for_decision(decision, risk_support, safety_support)` is
antisymmetric in `decision`: whenever `risk_support != safety_support`, flipping
the predicted side flips the target. The published contrast — side-correct
`0.7610` versus side-wrong `0.0632` — was therefore an identity of the labelling
function, not a measurement.

`src/vrf/evidence_targets.py` defines the replacement contract: an evidence
target is a function of the evidence only. `is_decision_invariant` enforces it
and is exercised by tests.

A second, shallower circularity surfaced during remediation and is now reported:
the human adjudications only ever confirmed windows the pipeline had already
proposed (10/10 subset, 0 outside), so the overlap metric cannot record a miss.
The report marks itself non-informative rather than publishing `1.0`.

### 4. Pair coupling now declares its closed-world assumption

`apply_pair_coupling` encodes knowledge that each group is a pair with exactly
one vulnerable member — a property of benchmark construction, not of deployment,
and not available to the baseline it was compared against.

The assumption is documented in the function, and
`scripts/evaluate_pair_coupled_constraint_decomposition.py` reports four systems
on the same groups so the constraint and the model can be read apart. The
decoder also no longer forces one positive on groups that are not two-row pairs
— group size is observable without labels, so this is a gold-free fix rather
than an oracle exclusion.

### 5. Inference moved to pair-group clustering

The five "split seeds" overlap pairwise at Jaccard `0.52–0.56` over the same 874
groups with frozen predictions. `src/vrf/stats_cluster.py` provides clustered
bootstrap and group-level exact tests keyed on `pair_key`. The honest interval
is **wider** than the one it replaces, as it must be.

### 6. The declared selector now matches the real one

`orientation_accuracy` is computed from `vuln_probability`, which pair coupling
never modifies, so it was constant across every margin and selection silently
fell to the `balanced_accuracy` tie-break. The default is now
`balanced_accuracy`, and `selection_scores` records
`primary_metric_discriminates`. The orientation sign-test is labelled
structurally invariant.

### 7. Gate precision reports its sample size

The preferred gate is the only variant defined for the only pool where the
original gate failed, and is preferred on that pool: selected-on-holdout. Its
precision is `1.0` at **n=4 pairs** (not 9 rows — the two rows of a pair are
mirror renderings of one patch), exact 95% CI `[0.3976, 1.0]`.

## Claim changes

| Previous wording | Corrected wording |
| --- | --- |
| "Negative controls stay near chance: metadata-only `0.5022`, candidate-only `0.5078`, counterpart-only `0.5156`." | "Three *diff-removing* controls stay near chance… These bound what metadata and single-side context contribute; they do **not** show the paired-diff formulation is shortcut-free, because none retains diff structure." |
| "Diff-only paired training is the credible mainline, with three-seed mean balanced accuracy `0.8287`." | "A rule reading only added/removed line counts is the correct comparison. The learned detector's margin over that floor is small, and it agrees with the floor on the large majority of rows." |
| "Pair-coupled decoding is the strongest system layer: five-split mean `0.8572`, delta `+0.0348`, bootstrap 95% CI `[0.0329, 0.0368]`." | "Pair coupling assumes group membership and exactly one vulnerable member per group — benchmark construction, not deployment. Reported against four baselines so the constraint is separated from the model." |
| "Evidence localization… Side-correct rows reach top-1 `0.7610`, side-wrong fall to `0.0632`, making error propagation measurable." | "Withdrawn: the target is antisymmetric in the predicted side, so the gap is an identity of the labelling function. Reported as heuristic consistency instead." |
| "Controls stay close to chance, protecting the paired diff formulation." | Withdrawn; replaced by an explicit statement of what the controls do and do not bound. |
| "eliminating relation violations (`0.3042 -> 0.0000`)" | "`0.3042 → 0.0000` is a **definitional identity** — the operator projects to `1 − p`. The measured quantities are the `0.0875` distortion rate and the `0.4033` randomized-pair control." |
| "model does not reduce to that heuristic (`~0.56` row agreement)" | Scoped to the VeriPatch-RR rendering, with an explicit warning that agreement on the pair-diff mainline is far higher. |
| Gate "`project_holdout_accept_precision` `1.0000`" | "`1.0` at n=4 pairs, exact 95% CI `[0.3976, 1.0]`, selected on the pool it is reported on." |

## What survived

The audit did not invalidate everything, and the remediation did not weaken
these:

- **Same-source success is artifact-sensitive.** `0.9524` collapsing to `0.4961`
  under paired evaluation remains the project's most defensible finding.
- **The three diff-removing controls are near chance.** As eval-set maxima they
  are conservative; the conclusion holds within its (now stated) scope.
- ~~**The model does carry signal beyond diff shape.**~~ **Withdrawn — see the
  adversarial validation section below.**
- **The preregistered readout results remain honestly negative.** No readout
  passes the canonical-delta rule, and the reports say so.

## Adversarial validation (second pass): the surviving claim was withdrawn

The remediation's own surviving claim — that under the pair constraint the
detector beats a semantics-free control by `+0.0682` — was then adversarially
tested and **did not survive**. Two defects were found in the remediation code
itself:

**Defect 1: contaminated baselines.** `apply_constraint` fell back to
`row["pred"]` — the *detector's* prediction — for the 40 groups the constraint
does not cover. Both the structural control and the random null silently
borrowed detector answers on 123 rows. The null therefore sat at `0.53` instead
of chance, and the control was inflated. Each system now carries its own
unconstrained fallback; the null is `0.4948`.

**Defect 2: the weakest control was chosen.** Only net *line* count was tested.
Net *character* count — equally semantics-free, reading no token content —
reaches BA `0.8627` unconstrained (above the detector's `0.8136`) and `0.8588`
under the pair constraint, against the detector's `0.8596`:

| comparison | delta | 95% clustered CI | group sign test |
| --- | ---: | ---: | --- |
| model vs net **line** rule | `+0.0738` | `[0.0478, 0.0999]` | 56–13, `p=1.7e-07` |
| model vs net **character** rule | `+0.0008` | `[-0.0202, +0.0225]` | 19–18, `p=1.0` |

The line-count rule is weak because it ties on ~22% of pairs and is then forced
to guess; on pairs where it does have an opinion the detector's margin is only
`+0.0095`. The character rule ties on ~4%. Under a fully predetermined detector
configuration (single model, threshold `0.5`, no calibrated routing) the
detector is *behind* the control at `-0.0055`, CI `[-0.0264, +0.0154]`.

**Consequence.** No signal beyond diff shape is demonstrated on this benchmark.
The detector is `0.2584` accurate on rows where the character rule errs — below
chance — so it fails harder where the structural signal fails, which is the
opposite of semantic reasoning.

**Standing rule added:** a model may only be described as outperforming a
structural shortcut after being compared against the *strongest* semantics-free
control available, never the first one tried.

## Standing reporting rules

1. Separate measured results from definitional identities.
2. Separate negative results from positive evidence.
3. Separate closed-world benchmark results from deployment claims.
4. Separate historical numbers from currently reproducible ones.
5. Passing unit tests are evidence of contract consistency, not scientific validity.
6. Never describe pseudo-label consistency as human-grounded localization accuracy.
7. Never compare only against chance when a strong structural heuristic exists.
8. Compare against the **strongest** semantics-free control, not the first one
   tried. A gap that vanishes against a better control was never model signal.
9. Every control must use its own unconstrained decision as a fallback. A
   baseline that borrows another system's predictions is not a baseline.

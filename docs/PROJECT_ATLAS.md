# Project Atlas

This atlas maps VeriSec Forge / VeriPatch-RR as a public research system. It is
not a paper substitute, a new experiment, or a benchmark release. Its purpose
is to show how the retained artifacts fit together and where each claim is
bounded.

For the machine-readable version, see `experiments/registry.json`. For a compact
reader-facing table, see `reports/EXPERIMENT_MATRIX.md`.

## 1. Measurement Layer

The measurement layer defines what is being evaluated before any model-quality
claim is considered.

- `reports/RELATIONAL_BENCHMARK_V2.md` defines VeriPatch-RR v0.1, including
  canonical paired rendering, side swaps, suffix perturbations, and
  visibility-qualified context pressure.
- `reports/PRIMEVUL_PROGRESSIVE_CONTROLS.md` and
  `reports/PRIMEVUL_MAIN_RESULTS.md` retain the benchmark-shortcut diagnosis
  that motivates paired-diff evaluation.
- `docs/COUNTERFACTUAL_SHORTCUT_PROTOCOL.md` and related reports document how
  relation-preserving perturbations are interpreted only when their expected
  relation is specified before evaluation.

Boundary: this layer defines measurement contracts and shortcut controls. It
does not claim a deployed vulnerability scanner or a tokenizer-neutral runtime
claim for every model.

## 2. Model Evidence Layer

The model evidence layer reports retained model-facing results under bounded
experimental conditions.

- `reports/VERIPATCH_RR_QWEN15B_SMOKE.md` records the frozen Qwen smoke result
  as an instrumented relational failure case.
- `reports/CROSS_MODEL_RELATIONAL_AUDIT.md` separates side-order inconsistency
  from endpoint sensitivity across Qwen and CodeBERT.
- `reports/CROSS_MODEL_REPLICATION.md` broadens stress coverage with
  distilgpt2 and generative-judge slots, while preserving the low-canonical
  stress boundary.
- `reports/PRIMEVUL_PAIR_COUPLED_SIGNIFICANCE.md` and related PrimeVul
  reports retain the paired-diff and pair-coupled decoding mainline.

Boundary: this layer supports a measurement claim about relational failures and
task-structured evaluation. It does not prove universal strong-model failure.

## 3. Mechanism Layer

The mechanism layer decomposes failure modes and controls readout-conditioned
endpoint sensitivity.

- `reports/QWEN_RELATIONAL_MECHANISM_AUDIT.md` separates context-cap changes,
  terminal-context sensitivity, and representation effects.
- `reports/READOUT_ABLATION.md` tests same-backbone readout variants.
- `reports/READOUT_CONFIRMATORY.md` independently confirms the mechanism
  pattern without promoting a better classifier.
- `reports/FROZEN_BACKBONE_READOUT_CONTROL.md` separates training-mediated and
  direct pooling effects under a fixed representation.
- `reports/QWEN_SIDE_SWAP_TERMINAL_PHRASE_INTERACTION.md` directly crosses
  the endpoint-collapse fix with side-swap equivariance and finds a ~14x
  smaller effect on the latter, confirming the two failure modes are largely
  separable rather than the same mechanism.
- `reports/QWEN_SIDE_SWAP_POSITIONAL_INDEPENDENCE.md` tests whether the
  side-swap failure is content-aware-but-mislabeled or content-blind:
  canonical and swapped predictions for the same pair are statistically
  independent (`phi = -0.024`, `p = 0.56`), while the same test under a
  non-swap intervention shows strong correlation (`phi = 0.80`), pointing to
  position-specific rather than content-symmetric processing.

Boundary: this layer supports mechanism evidence. It does not solve side-order
reasoning and does not promote readout variants as accuracy-preserving better
classifiers.

## 4. Reproducibility Layer

The reproducibility layer makes the retained public surface runnable and
auditable.

- `docs/VERIPATCH_RR_EXTERNAL_ADAPTER.md` defines the external prediction
  contract for `predict(text) -> A | B | A_RISKIER | B_RISKIER |
  INSUFFICIENT_CONTEXT`.
- `examples/veripatch_rr_smoke_30.jsonl` and its checked-in manifest provide a
  30-pair / 90-row adapter sanity check.
- `docs/CI_TESTING_STRATEGY.md` defines the focused fresh-clone smoke gate.
- `reproducibility/veripatch_external_smoke_manifest.json` pins the checked-in
  adapter smoke artifacts.

Boundary: the smoke artifact validates integration and packaging. It is not a
model-quality benchmark and is not tokenizer-neutral for other model runtime
claims.

## How To Read The System

1. Start with the README external reviewer path.
2. Use this atlas to understand the project layers.
3. Use `reports/EXPERIMENT_MATRIX.md` to find the report behind each retained
   claim.
4. Use `experiments/registry.json` when tooling or automated checks need the
   same map.

# Example: bounded claim edit

> **Worked examples use the current, scientifically supported result.**
> Under the closed-world pair constraint the detector reaches balanced accuracy
> `0.8596` and the strongest semantics-free structural control reaches `0.8588`;
> the delta is `+0.0008` with a pair-group clustered 95% CI spanning zero, so no
> semantic advantage beyond diff structure is established. Withdrawn values appear
> only inside an explicit audit example whose requested action is to reject the
> claim. Source of truth: `docs/RESULT_STATUS_LEDGER.md`.


## Before (too strong)

> Pair-coupled decoding achieves 0.86 accuracy and demonstrates that the model
> has learned secure patch reasoning.

## After (house style)

> Pair-coupled decoding is the strongest retained system layer on the closed
> PrimeVul paired-diff evaluation: constrained detector balanced accuracy
> `0.8596` versus strongest semantics-free structural control `0.8588`;
> delta `+0.0008`, pair-group clustered 95% CI `[-0.0202, +0.0222]`
> ([Pair-Coupled Significance](../../../../reports/PRIMEVUL_PAIR_COUPLED_SIGNIFICANCE.md)).
> This is task-structured decoding evidence under retained splits, **not** a
> claim of open-set expert discovery or human-level secure-patch reasoning.

## Checklist (from references/claim-boundary-checklist.md)

- [x] Number in `reports/`
- [x] CI + seed/split context
- [x] Boundary sentence
- [x] Evidence tier: model_evidence / system layer (not mechanism proof)

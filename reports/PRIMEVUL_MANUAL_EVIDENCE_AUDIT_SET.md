# PrimeVul Manual Evidence Audit Set

This report summarizes the first manual evidence-span audit target for the evidence-coupled paired-diff line.

## Summary

- Requested sample size: `50`
- Materialized rows: `42`
- Total candidate rows before pair-key deduplication: `100`
- Unique pair keys: `42`
- Output dataset: `data/processed/secure_code_primevul_manual_evidence_audit_v1.jsonl`

The materialized count can be smaller than the requested size because the current top-k side-inversion pools contain overlapping pair keys. This is a useful diagnostic: the first audit pool is intentionally high-signal but still small.

## Pool Counts

- `fresh_seeds_top5_v1`: `15`
- `project_holdout_top5_v1`: `8`
- `rank6_10_v1`: `13`
- `top5_v1`: `6`

## Gold Vulnerable Side Counts

- `A`: `26`
- `B`: `16`

## True Inversion Candidate Counts

- `False`: `26`
- `True`: `16`

## Annotation Contract

- `human_vulnerable_side`: `A`, `B`, or `unclear`.
- `evidence_side`: side supported by the selected evidence: `A`, `B`, `both`, `none`, or `unclear`.
- `evidence_quality`: `0` no usable evidence, `1` weak hint, `2` plausible evidence, `3` strong direct evidence.
- `selected_window_ids`: window IDs such as `A1`, `A2`, `B1` that justify the judgment.
- `label_issue`: `none`, `ambiguous`, `wrong_label`, or `insufficient_context`.
- `notes`: short free-text rationale.

## Intended Use

This audit set should be used to validate whether pseudo evidence windows actually support the vulnerable/fixed side decision. It is not a new benchmark score yet; it is the bridge from pseudo-label localization to human-checked evidence grounding.

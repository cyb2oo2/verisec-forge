# PrimeVul Manual Evidence Audit Set (Round 2)

This is the second-round manual evidence-span audit target, sampled from the same four
side-inversion review queues as round 1, excluding every `audit_id` *and* every `pair_key`
already used in `reports/PRIMEVUL_MANUAL_EVIDENCE_AUDIT_SET.md` -- the same review queue row
can appear multiple times across the four pools at different ranks/seeds, so deduplicating by
`audit_id` alone is not sufficient.

## Summary

- Round-1 rows excluded: `42`
- Round-1 pair keys excluded: `42`
- Unique pair keys across all four source queues: `42`
- Total candidate rows before exclusion and pair-key deduplication: `100`
- Materialized round-2 rows: `0`
- Unique pair keys: `0`
- Output dataset: `data/processed/secure_code_primevul_manual_evidence_audit_round2_v1.jsonl`

**This source is exhausted: `0` new pair keys remain.** The four review queues contain only `42` unique pair keys in total, and round 1's audit set already covers all of them. Widening the human-confirmed evidence set further requires a new upstream side-inversion candidate generation run (a different rank range, gap threshold, or seed family), not resampling these existing queue files.

## Pool Counts


## Annotation Contract

Same as round 1: `human_vulnerable_side`, `evidence_side`, `evidence_quality`,
`selected_window_ids`, `label_issue`, `notes`. This audit set ships with `annotation: null`
for every row; it requires an AI pilot pass (matching round 1's `codex_pilot` convention)
before `scripts/build_manual_evidence_pilot_findings.py` can classify rows into the
high-quality-disagreement and insufficient-context queues for human confirmation.

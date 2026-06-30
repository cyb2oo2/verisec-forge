# PrimeVul Manual Evidence Audit Set (Round 3)

This is the third-round manual evidence-span audit target: a rank-16-20
slice of the same underlying 592-pair scored pool used for rounds 1 and 2
(`data/processed/secure_code_primevul_paired_window_contrastive_eval_v1.jsonl`),
generated with `scripts/build_primevul_side_inversion_review_queue.py
--rank-start 16 --top-k 5`, excluding every `audit_id` and `pair_key`
already used in rounds 1 and 2.

## Summary

- Rounds 1+2 rows excluded: `61`
- Rounds 1+2 pair keys excluded: `61`
- New rank-16-20 queue: `25` rows / `25` unique pair keys
- Materialized round-3 rows: `14`, zero overlap with rounds 1-2
- Output dataset: `data/processed/secure_code_primevul_manual_evidence_audit_round3_v1.jsonl`

See `reports/PRIMEVUL_MANUAL_EVIDENCE_ROUND3_PENDING.md` for the AI pilot
pass, classification, and current (unconfirmed) status of this round.

## Pool Counts

- `rank16_20_v1`: `14`

## Annotation Contract

Same as round 1: `human_vulnerable_side`, `evidence_side`, `evidence_quality`,
`selected_window_ids`, `label_issue`, `notes`.
